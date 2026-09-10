package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetTenantSettings returns tenantID's saved anomaly-detection thresholds,
// or DefaultTenantSettings(tenantID) if it has never saved any.
func (s *Store) GetTenantSettings(ctx context.Context, tenantID string) (TenantSettings, error) {
	var t TenantSettings
	err := s.pool.QueryRow(ctx,
		`SELECT tenant_id, window_minutes, baseline_hours, min_baseline_events,
		        volume_ratio, share_shift, deny_rate_ratio, error_rate_ratio, latency_ratio, bulk_ratio, min_events, updated_at
		 FROM tenant_settings WHERE tenant_id = $1`, tenantID,
	).Scan(&t.TenantID, &t.WindowMinutes, &t.BaselineHours, &t.MinBaselineEvents,
		&t.VolumeRatio, &t.ShareShift, &t.DenyRateRatio, &t.ErrorRateRatio, &t.LatencyRatio, &t.BulkRatio, &t.MinEvents, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultTenantSettings(tenantID), nil
	}
	if err != nil {
		return TenantSettings{}, fmt.Errorf("loading tenant settings: %w", err)
	}
	return t, nil
}

// PutTenantSettings saves tenantID's thresholds, creating the row if this
// is the tenant's first save.
func (s *Store) PutTenantSettings(ctx context.Context, t TenantSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_settings
		    (tenant_id, window_minutes, baseline_hours, min_baseline_events,
		     volume_ratio, share_shift, deny_rate_ratio, error_rate_ratio, latency_ratio, bulk_ratio, min_events, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
		    window_minutes = EXCLUDED.window_minutes, baseline_hours = EXCLUDED.baseline_hours,
		    min_baseline_events = EXCLUDED.min_baseline_events, volume_ratio = EXCLUDED.volume_ratio,
		    share_shift = EXCLUDED.share_shift, deny_rate_ratio = EXCLUDED.deny_rate_ratio,
		    error_rate_ratio = EXCLUDED.error_rate_ratio, latency_ratio = EXCLUDED.latency_ratio,
		    bulk_ratio = EXCLUDED.bulk_ratio, min_events = EXCLUDED.min_events, updated_at = now()`,
		t.TenantID, t.WindowMinutes, t.BaselineHours, t.MinBaselineEvents,
		t.VolumeRatio, t.ShareShift, t.DenyRateRatio, t.ErrorRateRatio, t.LatencyRatio, t.BulkRatio, t.MinEvents,
	)
	if err != nil {
		return fmt.Errorf("saving tenant settings: %w", err)
	}
	return nil
}

// Validate reports whether t's thresholds are sane enough to save: every
// ratio and window strictly positive, share shift a fraction of 1. It does
// not second-guess whether the numbers are a *good* choice — that's what
// tuning after seeing false positives/negatives is for.
func (t TenantSettings) Validate() error {
	switch {
	case t.WindowMinutes <= 0:
		return fmt.Errorf("window_minutes must be positive")
	case t.BaselineHours <= 0:
		return fmt.Errorf("baseline_hours must be positive")
	case t.MinBaselineEvents <= 0:
		return fmt.Errorf("min_baseline_events must be positive")
	case t.MinEvents <= 0:
		return fmt.Errorf("min_events must be positive")
	case t.ShareShift <= 0 || t.ShareShift > 1:
		return fmt.Errorf("share_shift must be between 0 and 1")
	case t.VolumeRatio <= 1 || t.DenyRateRatio <= 1 || t.ErrorRateRatio <= 1 || t.LatencyRatio <= 1 || t.BulkRatio <= 1:
		return fmt.Errorf("volume_ratio, deny_rate_ratio, error_rate_ratio, latency_ratio, and bulk_ratio must all be greater than 1")
	}
	return nil
}
