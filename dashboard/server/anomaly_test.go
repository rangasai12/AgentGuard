package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"agentguard/dashboard/store"
)

// setupAnomalyAgent signs up a tenant and registers one agent through the
// real HTTP handlers (so tests exercise the same path production traffic
// does), returning the store, the session cookie, tenant/agent ids, and
// the agent's API key.
func setupAnomalyAgent(t *testing.T) (h http.Handler, s *store.Store, cookie *http.Cookie, tenantID, agentID, apiKey string) {
	t.Helper()
	h, s = testServer(t)

	signup := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Acme", "email": "u@acme.example", "password": "password123",
	}, nil)
	cookie = sessionCookieFrom(signup)
	tenantID = decodeBody[map[string]string](t, signup)["tenant_id"]
	createAgent := doJSON(t, h, "POST", "/api/agents?tenant_id="+tenantID, map[string]string{"name": "prod-agent"}, []*http.Cookie{cookie})
	agentID = decodeBody[map[string]string](t, createAgent)["agent_id"]
	regToken := decodeBody[map[string]string](t, createAgent)["registration_token"]
	register := doJSON(t, h, "POST", "/v1/agents/register", map[string]string{"registration_token": regToken}, nil)
	apiKey = decodeBody[map[string]string](t, register)["api_key"]
	return h, s, cookie, tenantID, agentID, apiKey
}

// hexID returns a 16-hex-char event id, unique per n, for events that need
// an outcome patch.
func hexID(n int) string { return fmt.Sprintf("%016x", n) }

// buildBaseline returns >= 50 events for version "1.0" in
// [baselineStart, baselineStart+few hours): a read/write mix, some
// reported outcomes with small exec times and small output sizes, and a
// couple of shell "runs" for the volume/per-run check.
func buildBaseline(baselineStart time.Time) []store.IngestedEvent {
	var events []store.IngestedEvent
	id := 1
	next := func() string { id++; return hexID(id) }

	for i := 0; i < 41; i++ {
		events = append(events, store.IngestedEvent{
			Timestamp: baselineStart.Add(time.Duration(i) * time.Minute), ActionType: "fs_read",
			Resource: fmt.Sprintf("/workspace/file%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}
	for i := 0; i < 5; i++ {
		events = append(events, store.IngestedEvent{
			Timestamp: baselineStart.Add(time.Duration(50+i) * time.Minute), ActionType: "fs_write",
			Resource: fmt.Sprintf("/workspace/out%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}
	// 5 reported reads on the same directory: small, consistent output —
	// the baseline the "scope" bulk check and the latency check compare
	// against (p95 output ~1000 bytes, p50 exec ~10ms).
	for i := 0; i < 5; i++ {
		eid := next()
		events = append(events,
			store.IngestedEvent{
				Timestamp: baselineStart.Add(time.Duration(60+i) * time.Minute), ActionType: "fs_read",
				Resource: fmt.Sprintf("/workspace/bulk%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0", EventID: eid,
			},
			store.IngestedEvent{
				Timestamp: baselineStart.Add(time.Duration(60+i)*time.Minute + time.Second), Kind: store.IngestKindOutcome, EventID: eid,
				Outcome: &store.EventOutcome{Status: "success", ExecMS: 10, OutputBytes: 1000},
			},
		)
	}
	// Two shell "runs" of 5 calls each — the baseline calls-per-run distribution.
	for r, runID := range []string{"base-run-a", "base-run-b"} {
		for i := 0; i < 5; i++ {
			events = append(events, store.IngestedEvent{
				Timestamp: baselineStart.Add(time.Duration(70+r*10+i) * time.Minute), ActionType: "shell",
				Resource: "somecmd --flag", Decision: "allow", MatchedRule: "r", AgentVersion: "1.0", RunID: runID,
			})
		}
	}
	return events
}

// buildWindowDeviations returns events in [windowStart, windowStart+1h)
// that deviate from buildBaseline in every one of the four kinds.
func buildWindowDeviations(windowStart time.Time) []store.IngestedEvent {
	var events []store.IngestedEvent
	id := 1000
	next := func() string { id++; return hexID(id) }

	// operation: the mix flips from mostly-read to mostly-write.
	events = append(events,
		store.IngestedEvent{Timestamp: windowStart, ActionType: "fs_read", Resource: "/workspace/w1.txt", Decision: "allow", MatchedRule: "r", AgentVersion: "1.0"},
		store.IngestedEvent{Timestamp: windowStart.Add(time.Minute), ActionType: "fs_read", Resource: "/workspace/w2.txt", Decision: "allow", MatchedRule: "r", AgentVersion: "1.0"},
	)
	for i := 0; i < 10; i++ {
		events = append(events, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(2+i) * time.Minute), ActionType: "fs_write",
			Resource: fmt.Sprintf("/workspace/wr%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}

	// system: a brand-new directory never touched during the baseline.
	events = append(events, store.IngestedEvent{
		Timestamp: windowStart.Add(15 * time.Minute), ActionType: "fs_read", Resource: "/newdir/secret.txt",
		Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
	})

	// operation: a burst of denies (network calls with no HTTP method
	// prefix classify as an unknown verb, so they don't disturb the
	// read/write share computed above).
	for i := 0; i < 5; i++ {
		events = append(events, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(16+i) * time.Minute), ActionType: "network",
			Resource: "blocked-host.example", Decision: "deny", MatchedRule: "no-network", AgentVersion: "1.0",
		})
	}

	// system: elevated error rate and elevated p50 latency, from the same
	// 5 reported calls (baseline was 0% errors at ~10ms).
	for i := 0; i < 5; i++ {
		eid := next()
		status := "success"
		if i < 3 {
			status = "error"
		}
		events = append(events,
			store.IngestedEvent{
				Timestamp: windowStart.Add(time.Duration(21+i) * time.Minute), ActionType: "fs_read",
				Resource: fmt.Sprintf("/workspace/err%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0", EventID: eid,
			},
			store.IngestedEvent{
				Timestamp: windowStart.Add(time.Duration(21+i)*time.Minute + time.Second), Kind: store.IngestKindOutcome, EventID: eid,
				Outcome: &store.EventOutcome{Status: status, ExecMS: 100},
			},
		)
	}

	// scope: one abnormally large call on a directory the baseline
	// already knows (so this doesn't also read as a new footprint).
	bulkID := next()
	events = append(events,
		store.IngestedEvent{
			Timestamp: windowStart.Add(30 * time.Minute), ActionType: "fs_read", Resource: "/workspace/hugefile.txt",
			Decision: "allow", MatchedRule: "r", AgentVersion: "1.0", EventID: bulkID,
		},
		store.IngestedEvent{
			Timestamp: windowStart.Add(30*time.Minute + time.Second), Kind: store.IngestKindOutcome, EventID: bulkID,
			Outcome: &store.EventOutcome{Status: "success", ExecMS: 100, OutputBytes: 50000},
		},
	)

	// volume: one run of 20 calls vs. a baseline of ~5 calls/run.
	for i := 0; i < 20; i++ {
		events = append(events, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(31+i) * time.Minute), ActionType: "shell",
			Resource: "somecmd --flag", Decision: "allow", MatchedRule: "r", AgentVersion: "1.0", RunID: "win-run-x",
		})
	}
	return events
}

func TestDetectAnomaliesAllKinds(t *testing.T) {
	_, s, _, tenantID, agentID, _ := setupAnomalyAgent(t)
	ctx := context.Background()

	// Computed as close as possible to the detect() call below so the two
	// never disagree about which hour "now" falls in.
	windowStart := time.Now().UTC().Truncate(time.Hour)
	baselineStart := windowStart.Add(-24 * time.Hour)

	if err := s.InsertEvents(ctx, tenantID, agentID, buildBaseline(baselineStart)); err != nil {
		t.Fatalf("InsertEvents baseline: %v", err)
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, buildWindowDeviations(windowStart)); err != nil {
		t.Fatalf("InsertEvents window: %v", err)
	}

	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if agent.LastAgentVersion != "1.0" {
		t.Fatalf("agent.LastAgentVersion = %q, want 1.0", agent.LastAgentVersion)
	}

	runner := newAnomalyRunner(s, newToolClassifier())
	n, err := runner.detect(ctx, agent)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if n == 0 {
		t.Fatalf("detect reported 0 anomalies, want several")
	}

	anomalies, err := s.ListAnomalies(ctx, tenantID, store.AnomalyFilter{})
	if err != nil {
		t.Fatalf("ListAnomalies: %v", err)
	}
	byKind := map[store.AnomalyKind][]store.Anomaly{}
	for _, a := range anomalies {
		byKind[a.Kind] = append(byKind[a.Kind], a)
	}

	wantKeys := map[store.AnomalyKind]string{
		store.AnomalySystem:    "fs_read:/newdir/",
		store.AnomalyOperation: "deny_rate",
		store.AnomalyScope:     "fs_read:/workspace/",
		store.AnomalyVolume:    "events_per_hour",
	}
	for kind, key := range wantKeys {
		found := false
		for _, a := range byKind[kind] {
			if a.Key == key {
				found = true
				if a.BaselineVersion != "1.0" {
					t.Errorf("%s/%s: BaselineVersion = %q, want 1.0", kind, key, a.BaselineVersion)
				}
			}
		}
		if !found {
			t.Errorf("expected a %s anomaly with key %q, got %+v", kind, key, byKind[kind])
		}
	}
	// The volume kind's per-run check and the system kind's latency/error
	// checks are separate keys within kinds already asserted above.
	foundLatencyOrError := false
	for _, a := range byKind[store.AnomalySystem] {
		if a.Key == "latency_p50" || a.Key == "error_rate" {
			foundLatencyOrError = true
		}
	}
	if !foundLatencyOrError {
		t.Errorf("expected a system latency_p50 or error_rate anomaly, got %+v", byKind[store.AnomalySystem])
	}
	foundCallsPerRun := false
	for _, a := range byKind[store.AnomalyVolume] {
		if a.Key == "calls_per_run" {
			foundCallsPerRun = true
		}
	}
	if !foundCallsPerRun {
		t.Errorf("expected a volume calls_per_run anomaly, got %+v", byKind[store.AnomalyVolume])
	}

	// Re-running detection for the same window upserts in place rather
	// than duplicating rows.
	n2, err := runner.detect(ctx, agent)
	if err != nil {
		t.Fatalf("second detect: %v", err)
	}
	anomalies2, err := s.ListAnomalies(ctx, tenantID, store.AnomalyFilter{})
	if err != nil {
		t.Fatalf("ListAnomalies after second detect: %v", err)
	}
	if len(anomalies2) != len(anomalies) {
		t.Fatalf("re-detecting the same window duplicated rows: first %d, second %d (n1=%d n2=%d)", len(anomalies), len(anomalies2), n, n2)
	}
}

func TestDetectAnomaliesFallsBackToPreviousVersion(t *testing.T) {
	_, s, _, tenantID, agentID, _ := setupAnomalyAgent(t)
	ctx := context.Background()

	windowStart := time.Now().UTC().Truncate(time.Hour)
	// Version 0.9 has plenty of history, but it stopped being used two
	// days ago — well before the 24h baseline window that ends at
	// windowStart, so a naive "same clock window" baseline would miss it.
	oldBaselineStart := windowStart.Add(-72 * time.Hour)
	if err := s.InsertEvents(ctx, tenantID, agentID, buildBaseline(oldBaselineStart)); err != nil {
		t.Fatalf("InsertEvents old version baseline: %v", err)
	}
	// Retag those events as version 0.9 by re-inserting under that
	// version instead (buildBaseline hard-codes "1.0"): simplest is to
	// build a second batch directly.
	oldEvents := buildBaseline(oldBaselineStart)
	for i := range oldEvents {
		oldEvents[i].AgentVersion = "0.9"
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, oldEvents); err != nil {
		t.Fatalf("InsertEvents 0.9: %v", err)
	}

	// Version 1.0 just started: a handful of events, far fewer than
	// MinBaselineEvents, all shortly before the window.
	var v10 []store.IngestedEvent
	for i := 0; i < 3; i++ {
		v10 = append(v10, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(-i-1) * time.Minute), ActionType: "fs_read",
			Resource: fmt.Sprintf("/workspace/new%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}
	// Something in the window itself, and one new scope key so detection
	// has something to report if it runs at all.
	v10 = append(v10, store.IngestedEvent{
		Timestamp: windowStart.Add(time.Minute), ActionType: "fs_read", Resource: "/onlyinwindow/x.txt",
		Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
	})
	if err := s.InsertEvents(ctx, tenantID, agentID, v10); err != nil {
		t.Fatalf("InsertEvents 1.0: %v", err)
	}

	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if agent.LastAgentVersion != "1.0" {
		t.Fatalf("agent.LastAgentVersion = %q, want 1.0", agent.LastAgentVersion)
	}

	runner := newAnomalyRunner(s, newToolClassifier())
	settings, err := s.GetTenantSettings(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantSettings: %v", err)
	}
	baselineVersion, _, _, baseline, err := runner.resolveBaseline(ctx, agent, "1.0", settings, windowStart)
	if err != nil {
		t.Fatalf("resolveBaseline: %v", err)
	}
	if baselineVersion != "0.9" {
		t.Fatalf("baselineVersion = %q, want 0.9 (fallback to previous version)", baselineVersion)
	}
	if baseline == nil || baseline.TotalCount < int64(settings.MinBaselineEvents) {
		t.Fatalf("fallback baseline = %+v, want >= %d events", baseline, settings.MinBaselineEvents)
	}
}

func TestDetectAnomaliesHonorsTenantThresholds(t *testing.T) {
	_, s, _, tenantID, agentID, _ := setupAnomalyAgent(t)
	ctx := context.Background()

	windowStart := time.Now().UTC().Truncate(time.Hour)
	baselineStart := windowStart.Add(-24 * time.Hour)
	if err := s.InsertEvents(ctx, tenantID, agentID, buildBaseline(baselineStart)); err != nil {
		t.Fatalf("InsertEvents baseline: %v", err)
	}
	// A mild share shift: window is 60% write, baseline ~10% write — a
	// 0.5 diff, which the default ShareShift (0.3) flags but a stricter
	// tenant-configured 0.9 does not.
	var window []store.IngestedEvent
	for i := 0; i < 4; i++ {
		window = append(window, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(i) * time.Minute), ActionType: "fs_write",
			Resource: fmt.Sprintf("/workspace/mild%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}
	for i := 0; i < 6; i++ {
		window = append(window, store.IngestedEvent{
			Timestamp: windowStart.Add(time.Duration(10+i) * time.Minute), ActionType: "fs_read",
			Resource: fmt.Sprintf("/workspace/mildr%d.txt", i), Decision: "allow", MatchedRule: "r", AgentVersion: "1.0",
		})
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, window); err != nil {
		t.Fatalf("InsertEvents window: %v", err)
	}

	agent, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	runner := newAnomalyRunner(s, newToolClassifier())

	// Stricter tenant threshold first (nothing written yet for this
	// window/key, so absence is unambiguous): the shift is not flagged.
	strict := store.DefaultTenantSettings(tenantID)
	strict.ShareShift = 0.9
	if err := s.PutTenantSettings(ctx, strict); err != nil {
		t.Fatalf("PutTenantSettings (strict): %v", err)
	}
	if _, err := runner.detect(ctx, agent); err != nil {
		t.Fatalf("detect (strict thresholds): %v", err)
	}
	anomaliesStrict, _ := s.ListAnomalies(ctx, tenantID, store.AnomalyFilter{})
	if anyOperationKey(anomaliesStrict, "write") {
		t.Fatalf("write share-shift anomaly must not fire under a stricter threshold, got %+v", anomaliesStrict)
	}

	// Back to defaults, same window: now it is flagged. UpsertAnomaly
	// never deletes a row that stops qualifying, but since the strict
	// pass above never inserted one, this is a clean first write.
	if err := s.PutTenantSettings(ctx, store.DefaultTenantSettings(tenantID)); err != nil {
		t.Fatalf("PutTenantSettings (default): %v", err)
	}
	if _, err := runner.detect(ctx, agent); err != nil {
		t.Fatalf("detect (default thresholds): %v", err)
	}
	anomaliesDefault, _ := s.ListAnomalies(ctx, tenantID, store.AnomalyFilter{})
	if !anyOperationKey(anomaliesDefault, "write") {
		t.Fatalf("expected a write share-shift anomaly under default thresholds, got %+v", anomaliesDefault)
	}
}

func anyOperationKey(anomalies []store.Anomaly, key string) bool {
	for _, a := range anomalies {
		if a.Kind == store.AnomalyOperation && a.Key == key {
			return true
		}
	}
	return false
}

func TestSettingsPutRequiresAdmin(t *testing.T) {
	h, _, cookie, tenantID, _, _ := setupAnomalyAgent(t)

	settings := doJSON(t, h, "GET", "/api/settings?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	if settings.Code != http.StatusOK {
		t.Fatalf("GET settings: status %d body %s", settings.Code, settings.Body.String())
	}
	got := decodeBody[map[string]any](t, settings)
	if got["window_minutes"] != float64(60) || got["share_shift"] != 0.3 {
		t.Fatalf("default settings = %v", got)
	}

	put := doJSON(t, h, "PUT", "/api/settings?tenant_id="+tenantID, map[string]any{
		"window_minutes": 30, "baseline_hours": 24, "min_baseline_events": 50,
		"volume_ratio": 3, "share_shift": 0.5, "deny_rate_ratio": 3, "error_rate_ratio": 3,
		"latency_ratio": 3, "bulk_ratio": 5, "min_events": 5,
	}, []*http.Cookie{cookie})
	if put.Code != http.StatusOK {
		t.Fatalf("PUT settings (admin): status %d body %s", put.Code, put.Body.String())
	}

	after := doJSON(t, h, "GET", "/api/settings?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	afterBody := decodeBody[map[string]any](t, after)
	if afterBody["window_minutes"] != float64(30) {
		t.Fatalf("settings after PUT = %v, want window_minutes 30", afterBody)
	}

	// A second tenant's admin cannot see or change the first tenant's
	// settings — the same withTenantAuth membership check every other
	// tenant-scoped endpoint uses (see TestWebAPIRejectsAccessToForeignTenant).
	otherSignup := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Other", "email": "owner@other.example", "password": "password123",
	}, nil)
	otherCookie := sessionCookieFrom(otherSignup)
	foreign := doJSON(t, h, "GET", "/api/settings?tenant_id="+tenantID, nil, []*http.Cookie{otherCookie})
	if foreign.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a foreign tenant's settings, got %d", foreign.Code)
	}

	invalid := doJSON(t, h, "PUT", "/api/settings?tenant_id="+tenantID, map[string]any{
		"window_minutes": -1, "baseline_hours": 24, "min_baseline_events": 50,
		"volume_ratio": 3, "share_shift": 0.5, "deny_rate_ratio": 3, "error_rate_ratio": 3,
		"latency_ratio": 3, "bulk_ratio": 5, "min_events": 5,
	}, []*http.Cookie{cookie})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative window_minutes, got %d", invalid.Code)
	}
}

func TestIngestTriggersAnomalyDetection(t *testing.T) {
	h, s, cookie, tenantID, agentID, apiKey := setupAnomalyAgent(t)
	ctx := context.Background()

	windowStart := time.Now().UTC().Truncate(time.Hour)
	baselineStart := windowStart.Add(-24 * time.Hour)
	baseline := buildBaseline(baselineStart)
	if err := s.InsertEvents(ctx, tenantID, agentID, baseline); err != nil {
		t.Fatalf("InsertEvents baseline: %v", err)
	}

	// Ship the window batch through the real ingest endpoint, exactly as
	// a forwarder would, including one brand-new scope key.
	body, _ := json.Marshal(map[string]any{"events": []store.IngestedEvent{
		{Timestamp: windowStart.Add(time.Minute), ActionType: "fs_read", Resource: "/newdir/secret.txt", Decision: "allow", MatchedRule: "r", AgentVersion: "1.0"},
	}})
	req := httptest.NewRequest("POST", "/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: status %d body %s", rec.Code, rec.Body.String())
	}

	anomalies := doJSON(t, h, "GET", "/api/anomalies?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	if anomalies.Code != http.StatusOK {
		t.Fatalf("GET anomalies: status %d body %s", anomalies.Code, anomalies.Body.String())
	}
	body2 := decodeBody[map[string]any](t, anomalies)
	list, _ := body2["anomalies"].([]any)
	found := false
	for _, it := range list {
		m := it.(map[string]any)
		if m["kind"] == "system" && m["key"] == "fs_read:/newdir/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ingest to have triggered detection of a new-footprint anomaly, got %v", list)
	}
}
