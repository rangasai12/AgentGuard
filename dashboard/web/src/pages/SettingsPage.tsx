import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import type { TenantSettings, ToolCatalogEntry } from "../api/types";

const VERBS = ["read", "write", "delete", "permission", "unknown"] as const;

// Every numeric field on TenantSettings, with the label/step/hint shown
// for it — one row of the form per entry, so adding a threshold later is
// one line here rather than a new block of markup.
const THRESHOLD_FIELDS: {
  key: keyof Omit<TenantSettings, "tenant_id" | "updated_at">;
  label: string;
  step?: string;
  hint: string;
}[] = [
  { key: "window_minutes", label: "Window (minutes)", hint: "How much recent activity counts as \"now\"." },
  { key: "baseline_hours", label: "Baseline (hours)", hint: "How far back \"normal\" is measured from." },
  { key: "min_baseline_events", label: "Min. baseline events", hint: "Below this, detection skips (warm-up)." },
  { key: "min_events", label: "Min. window events", hint: "A single event never trips a threshold." },
  { key: "volume_ratio", label: "Volume ratio", step: "0.1", hint: "Calls/hour or calls/run vs. baseline." },
  { key: "share_shift", label: "Share shift", step: "0.05", hint: "Change in read/write/delete/permission mix (0–1)." },
  { key: "deny_rate_ratio", label: "Deny rate ratio", step: "0.1", hint: "Denials vs. baseline denial rate." },
  { key: "error_rate_ratio", label: "Error rate ratio", step: "0.1", hint: "Tool errors vs. baseline error rate." },
  { key: "latency_ratio", label: "Latency ratio", step: "0.1", hint: "p50 execution time vs. baseline." },
  { key: "bulk_ratio", label: "Bulk ratio", step: "0.1", hint: "One call's output size vs. baseline p95." },
];

export function SettingsPage() {
  const { currentTenantId, currentMembership } = useAuth();
  const isAdmin = currentMembership?.role === "admin";

  const [form, setForm] = useState<TenantSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!currentTenantId) return;
    api.getSettings(currentTenantId).then(setForm).catch(() => {});
  }, [currentTenantId]);

  async function handleSave() {
    if (!currentTenantId || !form) return;
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      await api.putSettings(currentTenantId, form);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  const toolsFetcher = useCallback(async () => {
    if (!currentTenantId) return { tools: [] as ToolCatalogEntry[] };
    const result = await api.listTools(currentTenantId);
    return { tools: result.tools ?? [] };
  }, [currentTenantId]);
  const { data: toolsData, refetch: refetchTools } = usePolling(toolsFetcher, 30_000, [currentTenantId]);
  const tools = toolsData?.tools ?? [];

  const [overrideError, setOverrideError] = useState<string | null>(null);
  async function setVerb(tool: ToolCatalogEntry, verb: string) {
    if (!currentTenantId) return;
    setOverrideError(null);
    try {
      await api.setToolVerb(currentTenantId, tool.action_type, tool.resource, verb);
      refetchTools();
    } catch (err) {
      setOverrideError(err instanceof ApiError ? err.message : "Failed to set tool verb.");
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-header-text">
          <h1>Settings</h1>
          <p className="page-subtitle">Anomaly-detection thresholds and tool classification for this company.</p>
        </div>
      </div>

      <div className="panel settings-panel">
        <div className="panel-header">
          <h2>Detection thresholds</h2>
        </div>
        {saveError && <div className="form-error">{saveError}</div>}
        {!form ? (
          <div className="muted">Loading…</div>
        ) : (
          <>
            <div className="settings-grid">
              {THRESHOLD_FIELDS.map((f) => (
                <label key={f.key} className="settings-field">
                  {f.label}
                  <input
                    type="number"
                    step={f.step ?? "1"}
                    value={form[f.key]}
                    disabled={!isAdmin}
                    onChange={(e) => setForm({ ...form, [f.key]: Number(e.target.value) })}
                  />
                  <span className="field-hint">{f.hint}</span>
                </label>
              ))}
            </div>
            {isAdmin && (
              <div className="modal-actions">
                <button type="button" className="btn-primary" onClick={handleSave} disabled={saving}>
                  {saving ? "Saving…" : saved ? "Saved" : "Save thresholds"}
                </button>
              </div>
            )}
            {!isAdmin && <p className="field-hint">Only an admin can change these.</p>}
          </>
        )}
      </div>

      <div className="panel settings-panel">
        <div className="panel-header">
          <h2>Tool classification</h2>
        </div>
        {overrideError && <div className="form-error">{overrideError}</div>}
        {tools.length === 0 ? (
          <div className="empty-state small">No tools observed yet.</div>
        ) : (
          <table className="data-table compact">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Description</th>
                <th>Verb</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={`${tool.action_type}:${tool.resource}`}>
                  <td className="mono">{tool.resource}</td>
                  <td className="muted">{tool.description || "—"}</td>
                  <td>
                    {isAdmin ? (
                      <select
                        className="verb-select"
                        value={tool.verb || "unknown"}
                        onChange={(e) => setVerb(tool, e.target.value)}
                      >
                        {VERBS.map((v) => (
                          <option key={v} value={v}>
                            {v}
                          </option>
                        ))}
                      </select>
                    ) : (
                      tool.verb || "unknown"
                    )}
                  </td>
                  <td className="muted" title={tool.verb_reason || undefined}>
                    {tool.verb_source || "unclassified"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
