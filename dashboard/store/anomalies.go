package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// UpsertAnomaly inserts one detected deviation, or — if detection already
// reported this exact (agent_id, kind, key, window_start) — updates its
// score/detail in place. Acknowledgement columns are never touched by the
// update branch, so re-detecting an already-acknowledged anomaly within
// the same window does not silently reopen it.
func (s *Store) UpsertAnomaly(ctx context.Context, a Anomaly) error {
	if a.ID == "" {
		a.ID = newID("anom")
	}
	detail := a.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO anomalies
		    (id, tenant_id, agent_id, agent_version, kind, key, score, detail,
		     window_start, window_end, baseline_start, baseline_end, baseline_version, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
		ON CONFLICT (agent_id, kind, key, window_start) DO UPDATE SET
		    score = EXCLUDED.score, detail = EXCLUDED.detail, agent_version = EXCLUDED.agent_version,
		    baseline_start = EXCLUDED.baseline_start, baseline_end = EXCLUDED.baseline_end,
		    baseline_version = EXCLUDED.baseline_version, detected_at = now()`,
		a.ID, a.TenantID, a.AgentID, a.AgentVersion, string(a.Kind), a.Key, a.Score, string(detail),
		a.WindowStart, a.WindowEnd, a.BaselineStart, a.BaselineEnd, a.BaselineVersion,
	)
	if err != nil {
		return fmt.Errorf("upserting anomaly: %w", err)
	}
	return nil
}

// ListAnomalies returns tenantID's detected anomalies, most recent first.
func (s *Store) ListAnomalies(ctx context.Context, tenantID string, filter AnomalyFilter) ([]Anomaly, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	where := "anomalies.tenant_id = $1"
	args := []any{tenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND %s $%d", clause, len(args))
	}
	if filter.AgentID != "" {
		add("anomalies.agent_id =", filter.AgentID)
	}
	if filter.Unacknowledged {
		where += " AND anomalies.acknowledged_at IS NULL"
	}
	if filter.Since != nil {
		add("anomalies.detected_at >=", *filter.Since)
	}
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, `
		SELECT anomalies.id, anomalies.tenant_id, anomalies.agent_id, agents.name, anomalies.agent_version,
		       anomalies.kind, anomalies.key, anomalies.score, anomalies.detail,
		       anomalies.window_start, anomalies.window_end, anomalies.baseline_start, anomalies.baseline_end, anomalies.baseline_version,
		       anomalies.detected_at, COALESCE(anomalies.acknowledged_by, ''), anomalies.acknowledged_at
		FROM anomalies JOIN agents ON agents.id = anomalies.agent_id
		WHERE `+where+`
		ORDER BY anomalies.detected_at DESC LIMIT $`+fmt.Sprint(len(args)), args...,
	)
	if err != nil {
		return nil, fmt.Errorf("listing anomalies: %w", err)
	}
	defer rows.Close()
	var out []Anomaly
	for rows.Next() {
		var a Anomaly
		var detail []byte
		var kind string
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AgentID, &a.AgentName, &a.AgentVersion,
			&kind, &a.Key, &a.Score, &detail,
			&a.WindowStart, &a.WindowEnd, &a.BaselineStart, &a.BaselineEnd, &a.BaselineVersion,
			&a.DetectedAt, &a.AcknowledgedBy, &a.AcknowledgedAt); err != nil {
			return nil, err
		}
		a.Kind = AnomalyKind(kind)
		a.Detail = json.RawMessage(detail)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckAnomaly marks one of tenantID's anomalies acknowledged by userID.
func (s *Store) AckAnomaly(ctx context.Context, tenantID, anomalyID, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE anomalies SET acknowledged_by = $3, acknowledged_at = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantID, anomalyID, userID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("acknowledging anomaly: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
