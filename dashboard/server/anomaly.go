// anomaly.go runs rules-free behavioral anomaly detection after ingest:
// for one agent's current version, compare the last window of activity
// against a rolling baseline (the same version's own recent history, or
// the previous version's, derived automatically — nobody hand-defines a
// baseline) and report deviations in four kinds: system (a new footprint,
// or elevated error rate/latency), operation (a shift in the read/write/
// delete/permission mix, or deny rate), scope (an abnormally large single
// call), and volume (elevated call rate, overall or per run). See
// CHANGELOG.md for the full design and its deferred edges.
package server

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"agentguard/dashboard/store"
	"agentguard/engine"
)

// anomalyMinInterval throttles detection to at most once per agent this
// often — ingest can call maybeRun on every batch without re-running the
// full comparison on every one.
const anomalyMinInterval = 60 * time.Second

// anomalyRunner holds the one piece of state detection needs across calls:
// when each agent was last checked. There is no ticker and no queue —
// detection runs synchronously, triggered from ingest, bounded by the
// caller's context — matching the rest of this codebase's deliberate
// "no scheduler" simplicity (see CHANGELOG's Phase 1/4 entries).
type anomalyRunner struct {
	store      *store.Store
	classifier *toolClassifier
	lastRun    sync.Map // agent id -> time.Time
}

func newAnomalyRunner(s *store.Store, c *toolClassifier) *anomalyRunner {
	return &anomalyRunner{store: s, classifier: c}
}

// classifyBudget bounds one classification pass — generous relative to
// detectBudget because it can involve several sequential live LLM calls
// (one per newly-seen tool) the first time a batch of new tools shows up,
// which is rare (throttled the same as detection) but should not be cut
// off partway through by a budget sized for detection's much cheaper SQL
// queries. See the "two independent timeouts" note on maybeRun.
const classifyBudget = 25 * time.Second
const detectBudget = 5 * time.Second

// maybeRun classifies any of agent's tenant's tools that don't have a verb
// yet, then runs anomaly detection for agent — but only if at least
// anomalyMinInterval has passed since the last time this agent was
// checked. Errors are logged, never returned: a detection failure must
// never make an otherwise-successful event batch look unaccepted to the
// forwarder that sent it. Classification and detection each get their own
// timeout derived from ctx, rather than sharing one budget — a slow batch
// of live classifier calls must never starve detection of the time it
// needs to run at all (this was a real bug: a single busy ingest with
// several new tools ran classification, its ctx expired mid-loop, and
// detection then failed immediately too because it inherited an
// already-cancelled context).
func (r *anomalyRunner) maybeRun(ctx context.Context, agent store.Agent) {
	now := time.Now()
	if last, ok := r.lastRun.Load(agent.ID); ok {
		if now.Sub(last.(time.Time)) < anomalyMinInterval {
			return
		}
	}
	r.lastRun.Store(agent.ID, now)

	classifyCtx, cancel := context.WithTimeout(ctx, classifyBudget)
	if err := r.classifier.classifyUnclassified(classifyCtx, r.store, agent.TenantID); err != nil {
		log.Printf("agentguard-cloud: classifying tools for tenant %s: %v", agent.TenantID, err)
	}
	cancel()

	detectCtx, cancel := context.WithTimeout(ctx, detectBudget)
	if _, err := r.detect(detectCtx, agent); err != nil {
		log.Printf("agentguard-cloud: detecting anomalies for agent %s: %v", agent.ID, err)
	}
	cancel()
}

// detect runs one detection pass for agent's current version and returns
// how many anomaly rows it wrote (for tests). It is exported to this
// package's tests directly (bypassing the throttle) so they can assert on
// specific windows without racing maybeRun's interval.
func (r *anomalyRunner) detect(ctx context.Context, agent store.Agent) (int, error) {
	version := agent.LastAgentVersion
	if version == "" {
		return 0, nil
	}
	settings, err := r.store.GetTenantSettings(ctx, agent.TenantID)
	if err != nil {
		return 0, err
	}

	// The window is the current hour (or however many minutes the tenant
	// configures), aligned to the hour so repeated runs within it produce
	// the same window_start and upsert the same anomaly rows rather than
	// duplicating them.
	windowStart := time.Now().UTC().Truncate(time.Hour)
	windowEnd := windowStart.Add(time.Duration(settings.WindowMinutes) * time.Minute)
	windowFilter := store.MetricsFilter{AgentID: agent.ID, AgentVersion: version, Since: &windowStart, Until: &windowEnd}
	window, err := r.store.Metrics(ctx, agent.TenantID, windowFilter)
	if err != nil {
		return 0, err
	}
	if window.TotalCount == 0 {
		return 0, nil
	}

	baselineVersion, baselineStart, baselineEnd, baseline, err := r.resolveBaseline(ctx, agent, version, settings, windowStart)
	if err != nil {
		return 0, err
	}
	if baseline == nil {
		return 0, nil // not enough history yet (warm-up) — nothing to compare against
	}
	baselineFilter := store.MetricsFilter{AgentID: agent.ID, AgentVersion: baselineVersion, Since: &baselineStart, Until: &baselineEnd}

	var anomalies []store.Anomaly

	systemAnomalies, err := r.detectSystem(ctx, agent, version, window, *baseline, windowStart, windowEnd, baselineVersion, baselineStart, baselineEnd, settings)
	if err != nil {
		return 0, err
	}
	operationAnomalies, err := r.detectOperation(ctx, agent, window, *baseline, windowFilter, baselineFilter, settings)
	if err != nil {
		return 0, err
	}
	scopeAnomalies, err := r.detectScope(ctx, agent, windowFilter, baselineFilter, settings)
	if err != nil {
		return 0, err
	}
	volumeAnomalies, err := r.detectVolume(ctx, agent, window, *baseline, windowFilter, baselineFilter, settings)
	if err != nil {
		return 0, err
	}
	anomalies = append(anomalies, systemAnomalies...)
	anomalies = append(anomalies, operationAnomalies...)
	anomalies = append(anomalies, scopeAnomalies...)
	anomalies = append(anomalies, volumeAnomalies...)

	for i := range anomalies {
		anomalies[i].TenantID = agent.TenantID
		anomalies[i].AgentID = agent.ID
		anomalies[i].AgentVersion = version
		anomalies[i].WindowStart, anomalies[i].WindowEnd = windowStart, windowEnd
		anomalies[i].BaselineStart, anomalies[i].BaselineEnd = &baselineStart, &baselineEnd
		anomalies[i].BaselineVersion = baselineVersion
		if err := r.store.UpsertAnomaly(ctx, anomalies[i]); err != nil {
			return len(anomalies), err
		}
	}
	return len(anomalies), nil
}

// resolveBaseline picks what to compare the window against: the same
// version's own activity in the baselineHours before the window if that's
// at least MinBaselineEvents, else the previous version's own last
// baselineHours of activity (its own lifetime, not the same clock window —
// a retired version's "recent" history is whenever it was last used), else
// nil (skip — not enough data yet, a documented warm-up gap).
func (r *anomalyRunner) resolveBaseline(ctx context.Context, agent store.Agent, version string, settings store.TenantSettings, windowStart time.Time) (baselineVersion string, start, end time.Time, m *store.Metrics, err error) {
	baselineHours := time.Duration(settings.BaselineHours) * time.Hour
	end = windowStart
	start = end.Add(-baselineHours)

	sameVersion, err := r.store.Metrics(ctx, agent.TenantID, store.MetricsFilter{AgentID: agent.ID, AgentVersion: version, Since: &start, Until: &end})
	if err != nil {
		return "", time.Time{}, time.Time{}, nil, err
	}
	if sameVersion.TotalCount >= int64(settings.MinBaselineEvents) {
		return version, start, end, &sameVersion, nil
	}

	idx := -1
	for i, v := range sameVersion.Versions {
		if v.AgentVersion == version {
			idx = i
			break
		}
	}
	if idx < 0 || idx+1 >= len(sameVersion.Versions) {
		return "", time.Time{}, time.Time{}, nil, nil
	}
	prev := sameVersion.Versions[idx+1]
	pEnd := prev.LastSeen
	if pEnd.After(windowStart) {
		pEnd = windowStart
	}
	pStart := pEnd.Add(-baselineHours)
	prevMetrics, err := r.store.Metrics(ctx, agent.TenantID, store.MetricsFilter{AgentID: agent.ID, AgentVersion: prev.AgentVersion, Since: &pStart, Until: &pEnd})
	if err != nil {
		return "", time.Time{}, time.Time{}, nil, err
	}
	if prevMetrics.TotalCount < int64(settings.MinBaselineEvents) {
		return "", time.Time{}, time.Time{}, nil, nil
	}
	return prev.AgentVersion, pStart, pEnd, &prevMetrics, nil
}

// detectSystem: new footprint (scope keys never seen at this version's
// baseline), plus elevated error rate and p50 latency.
func (r *anomalyRunner) detectSystem(
	ctx context.Context, agent store.Agent, version string, window, baseline store.Metrics,
	windowStart, windowEnd time.Time, baselineVersion string, baselineStart, baselineEnd time.Time,
	settings store.TenantSettings,
) ([]store.Anomaly, error) {
	var out []store.Anomaly

	newKeys, err := r.store.NewScopeKeys(ctx, agent.TenantID, agent.ID, version, windowStart, windowEnd, baselineVersion, baselineStart, baselineEnd, 25)
	if err != nil {
		return nil, err
	}
	for _, k := range newKeys {
		detail, _ := json.Marshal(map[string]any{"scope_key": k.Value, "window_count": k.Count})
		out = append(out, store.Anomaly{Kind: store.AnomalySystem, Key: k.Value, Score: float64(k.Count), Detail: detail})
	}

	windowErrorRate := rateOf(window.ErrorCount, window.ReportedCount)
	baselineErrorRate := rateOf(baseline.ErrorCount, baseline.ReportedCount)
	if anomalous, score := ratioAnomaly(windowErrorRate, baselineErrorRate, settings.ErrorRateRatio, window.ReportedCount, int64(settings.MinEvents)); anomalous {
		detail, _ := json.Marshal(map[string]any{"window_error_rate": windowErrorRate, "baseline_error_rate": baselineErrorRate})
		out = append(out, store.Anomaly{Kind: store.AnomalySystem, Key: "error_rate", Score: score, Detail: detail})
	}

	if window.ExecP50MS != nil && baseline.ExecP50MS != nil {
		if anomalous, score := ratioAnomaly(*window.ExecP50MS, *baseline.ExecP50MS, settings.LatencyRatio, window.ExecSamples, int64(settings.MinEvents)); anomalous {
			detail, _ := json.Marshal(map[string]any{"window_p50_ms": *window.ExecP50MS, "baseline_p50_ms": *baseline.ExecP50MS})
			out = append(out, store.Anomaly{Kind: store.AnomalySystem, Key: "latency_p50", Score: score, Detail: detail})
		}
	}
	return out, nil
}

// operationVerbs are the buckets share-shift is computed over; unknown
// calls (unclassified tools, or a heuristic that couldn't tell) are
// excluded from the share per the design in CHANGELOG.md.
var operationVerbs = []engine.Verb{engine.VerbRead, engine.VerbWrite, engine.VerbDelete, engine.VerbPermission}

// detectOperation: a shift in the read/write/delete/permission mix, or an
// elevated deny rate.
func (r *anomalyRunner) detectOperation(
	ctx context.Context, agent store.Agent, window, baseline store.Metrics,
	windowFilter, baselineFilter store.MetricsFilter, settings store.TenantSettings,
) ([]store.Anomaly, error) {
	windowVerbs, err := r.store.VerbCounts(ctx, agent.TenantID, windowFilter)
	if err != nil {
		return nil, err
	}
	baselineVerbs, err := r.store.VerbCounts(ctx, agent.TenantID, baselineFilter)
	if err != nil {
		return nil, err
	}

	var out []store.Anomaly
	windowTotal, baselineTotal := sumVerbs(windowVerbs), sumVerbs(baselineVerbs)
	if windowTotal >= int64(settings.MinEvents) && baselineTotal > 0 {
		for _, v := range operationVerbs {
			windowShare := float64(windowVerbs[v]) / float64(windowTotal)
			baselineShare := float64(baselineVerbs[v]) / float64(baselineTotal)
			diff := windowShare - baselineShare
			if diff < 0 {
				diff = -diff
			}
			if diff >= settings.ShareShift {
				detail, _ := json.Marshal(map[string]any{
					"window_share": windowShare, "baseline_share": baselineShare, "window_count": windowVerbs[v],
				})
				out = append(out, store.Anomaly{Kind: store.AnomalyOperation, Key: string(v), Score: diff, Detail: detail})
			}
		}
	}

	windowDenyRate := rateOf(window.DenyCount, window.TotalCount)
	baselineDenyRate := rateOf(baseline.DenyCount, baseline.TotalCount)
	if anomalous, score := ratioAnomaly(windowDenyRate, baselineDenyRate, settings.DenyRateRatio, window.DenyCount, int64(settings.MinEvents)); anomalous {
		detail, _ := json.Marshal(map[string]any{"window_deny_rate": windowDenyRate, "baseline_deny_rate": baselineDenyRate})
		out = append(out, store.Anomaly{Kind: store.AnomalyOperation, Key: "deny_rate", Score: score, Detail: detail})
	}
	return out, nil
}

// detectScope: a single reported call whose output is far bigger than
// anything that scope key produced during the baseline. Argument-shape
// changes (single id -> list/wildcard) are a documented deferred gap —
// see CHANGELOG.md.
func (r *anomalyRunner) detectScope(
	ctx context.Context, agent store.Agent, windowFilter, baselineFilter store.MetricsFilter, settings store.TenantSettings,
) ([]store.Anomaly, error) {
	windowStats, err := r.store.ScopeOutputStats(ctx, agent.TenantID, windowFilter)
	if err != nil {
		return nil, err
	}
	baselineStats, err := r.store.ScopeOutputStats(ctx, agent.TenantID, baselineFilter)
	if err != nil {
		return nil, err
	}

	var out []store.Anomaly
	for key, w := range windowStats {
		b, ok := baselineStats[key]
		if !ok || b.Samples < int64(settings.MinEvents) || b.P95 <= 0 {
			continue
		}
		ratio := float64(w.Max) / b.P95
		if ratio >= settings.BulkRatio {
			detail, _ := json.Marshal(map[string]any{"window_max_bytes": w.Max, "baseline_p95_bytes": b.P95})
			out = append(out, store.Anomaly{Kind: store.AnomalyScope, Key: key, Score: ratio, Detail: detail})
		}
	}
	return out, nil
}

// detectVolume: an elevated overall call rate, and — when the SDK's run
// grouping is in use — an elevated average calls-per-run.
func (r *anomalyRunner) detectVolume(
	ctx context.Context, agent store.Agent, window, baseline store.Metrics,
	windowFilter, baselineFilter store.MetricsFilter, settings store.TenantSettings,
) ([]store.Anomaly, error) {
	var out []store.Anomaly

	if anomalous, score := ratioAnomaly(window.EventsPerHour, baseline.EventsPerHour, settings.VolumeRatio, window.TotalCount, int64(settings.MinEvents)); anomalous {
		detail, _ := json.Marshal(map[string]any{"window_events_per_hour": window.EventsPerHour, "baseline_events_per_hour": baseline.EventsPerHour})
		out = append(out, store.Anomaly{Kind: store.AnomalyVolume, Key: "events_per_hour", Score: score, Detail: detail})
	}

	windowRuns, err := r.store.RunEventCounts(ctx, agent.TenantID, windowFilter)
	if err != nil {
		return nil, err
	}
	baselineRuns, err := r.store.RunEventCounts(ctx, agent.TenantID, baselineFilter)
	if err != nil {
		return nil, err
	}
	if len(windowRuns) > 0 && len(baselineRuns) > 0 {
		windowAvg, baselineAvg := avgCount(windowRuns), avgCount(baselineRuns)
		if anomalous, score := ratioAnomaly(windowAvg, baselineAvg, settings.VolumeRatio, int64(len(windowRuns)), 1); anomalous {
			detail, _ := json.Marshal(map[string]any{
				"window_avg_calls_per_run": windowAvg, "baseline_avg_calls_per_run": baselineAvg, "window_runs": len(windowRuns),
			})
			out = append(out, store.Anomaly{Kind: store.AnomalyVolume, Key: "calls_per_run", Score: score, Detail: detail})
		}
	}
	return out, nil
}

// rateOf is num/den, or 0 when den is 0 (rather than NaN) — every rate
// this file computes goes through this one definition.
func rateOf(num, den int64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// ratioAnomaly reports whether currentRate has grown at least ratio times
// baselineRate, and the observed ratio as a score. Requires at least
// minCount samples in the current window so a single event can never trip
// a threshold. A zero baseline rate with any nonzero current rate over
// minCount samples still counts as anomalous — "this never happened during
// the baseline, and now it does" has no ratio to compute, but is exactly
// what this check exists to catch.
func ratioAnomaly(currentRate, baselineRate, ratio float64, currentCount, minCount int64) (bool, float64) {
	if currentCount < minCount {
		return false, 0
	}
	if baselineRate <= 0 {
		return currentRate > 0, currentRate
	}
	observed := currentRate / baselineRate
	return observed >= ratio, observed
}

func sumVerbs(counts map[engine.Verb]int64) int64 {
	var total int64
	for _, v := range operationVerbs {
		total += counts[v]
	}
	return total
}

func avgCount(counts []store.ResourceCount) float64 {
	if len(counts) == 0 {
		return 0
	}
	var total int64
	for _, c := range counts {
		total += c.Count
	}
	return float64(total) / float64(len(counts))
}
