import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { DecisionBadge } from "../components/DecisionBadge";
import { MiniStat } from "../components/MiniStat";
import { Avatar } from "../components/Avatar";
import { timeAgo } from "../lib/time";
import type { Agent, AuditEvent } from "../api/types";

const POLL_INTERVAL_MS = 4_000;

function downloadCsv(events: AuditEvent[]) {
  const header = [
    "timestamp",
    "agent",
    "actor",
    "action_type",
    "resource",
    "decision",
    "matched_rule",
    "reason",
    "latency_ms",
    "event_id",
    "run_id",
    "agent_version",
    "outcome",
    "exec_ms",
  ];
  const rows = events.map((e) => [
    e.timestamp,
    e.agent_name || e.agent_id,
    e.actor || "",
    e.action_type,
    e.resource,
    e.decision,
    e.matched_rule || "",
    e.reason || "",
    String(e.latency_ms ?? ""),
    e.event_id || "",
    e.run_id || "",
    e.agent_version || "",
    e.outcome?.status || "",
    e.outcome ? String(e.outcome.exec_ms) : "",
  ]);
  const csv = [header, ...rows]
    .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `agentguard-events-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function copyText(text: string, onDone: () => void) {
  try {
    await navigator.clipboard.writeText(text);
    onDone();
  } catch {
    // Clipboard API may be unavailable; the value is still visible on screen.
  }
}

export function EventsPage() {
  const { currentTenantId } = useAuth();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentId, setAgentId] = useState("");
  const [actionType, setActionType] = useState("");
  const [decision, setDecision] = useState("");
  const [resourceContains, setResourceContains] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState<"details" | "raw">("details");
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!currentTenantId) return;
    api.listAgents(currentTenantId).then((r) => setAgents(r.agents ?? [])).catch(() => {});
  }, [currentTenantId]);

  const fetcher = useCallback(async () => {
    if (!currentTenantId) return { events: [] as AuditEvent[] };
    const result = await api.listEvents(currentTenantId, {
      agent_id: agentId || undefined,
      action_type: actionType || undefined,
      decision: decision || undefined,
      resource_contains: resourceContains || undefined,
      since: since ? new Date(since).toISOString() : undefined,
      until: until ? new Date(until).toISOString() : undefined,
      limit: 200,
    });
    // Backend returns `{"events":null}` when there are none.
    return { events: result.events ?? [] };
  }, [currentTenantId, agentId, actionType, decision, resourceContains, since, until]);

  const { data, error, loading } = usePolling(fetcher, POLL_INTERVAL_MS, [
    currentTenantId,
    agentId,
    actionType,
    decision,
    resourceContains,
    since,
    until,
  ]);

  const events = data?.events ?? [];

  // Keep a selection alive across polling refreshes; fall back to the most
  // recent event if the previously selected one aged out of the window.
  useEffect(() => {
    if (events.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!events.some((e) => e.id === selectedId)) {
      setSelectedId(events[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events]);

  const selectedEvent = events.find((e) => e.id === selectedId) ?? null;

  const activeFilterCount = [agentId, actionType, decision, resourceContains, since, until].filter(
    (v) => v !== "",
  ).length;

  function clearFilters() {
    setAgentId("");
    setActionType("");
    setDecision("");
    setResourceContains("");
    setSince("");
    setUntil("");
  }

  const summary = useMemo(() => {
    const allow = events.filter((e) => e.decision === "allow").length;
    const deny = events.filter((e) => e.decision === "deny").length;
    const avgLatency = events.length
      ? Math.round(events.reduce((sum, e) => sum + (e.latency_ms || 0), 0) / events.length)
      : 0;
    return { allow, deny, avgLatency };
  }, [events]);

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-header-text">
          <h1>
            Live Feed
            {events.length > 0 && <span className="count-chip">{events.length}</span>}
          </h1>
          <p className="page-subtitle">Every policy decision across your fleet, polled every 4s.</p>
        </div>
        <button type="button" className="btn-secondary" onClick={() => downloadCsv(events)} disabled={events.length === 0}>
          Export CSV
        </button>
      </div>

      <div className="filter-bar">
        <label>
          Agent
          <select value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Action type
          <input
            type="text"
            value={actionType}
            onChange={(e) => setActionType(e.target.value)}
            placeholder="e.g. shell.exec"
          />
        </label>
        <label>
          Decision
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="">All decisions</option>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
            <option value="require_approval">require_approval</option>
          </select>
        </label>
        <label>
          Resource contains
          <input
            type="text"
            value={resourceContains}
            onChange={(e) => setResourceContains(e.target.value)}
            placeholder="substring search"
          />
        </label>
        <label>
          Since
          <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
        </label>
        <label>
          Until
          <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
        </label>
        <button type="button" className="btn-link" onClick={clearFilters} disabled={activeFilterCount === 0}>
          Clear filters{activeFilterCount ? ` (${activeFilterCount})` : ""}
        </button>
      </div>

      {error && <div className="form-error">{error}</div>}

      {loading && !data ? (
        <div className="page-center">Loading…</div>
      ) : events.length === 0 ? (
        <div className="empty-state">No events match these filters.</div>
      ) : (
        <>
          <div className="mini-stat-grid">
            <MiniStat label="Allowed (this view)" value={summary.allow} />
            <MiniStat label="Denied (this view)" value={summary.deny} />
            <MiniStat label="Avg. latency" value={summary.avgLatency} suffix="ms" />
          </div>

          <div className="split-view">
            <div className="split-list">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Agent</th>
                    <th>Actor</th>
                    <th>Action type</th>
                    <th>Resource</th>
                    <th>Decision</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr
                      key={event.id}
                      className={"clickable" + (event.id === selectedId ? " selected" : "")}
                      onClick={() => setSelectedId(event.id)}
                    >
                      <td className="muted" title={new Date(event.timestamp).toLocaleString()}>
                        {timeAgo(event.timestamp)}
                      </td>
                      <td>
                        <span className="name-cell">
                          <Avatar label={event.agent_name || event.agent_id} size={20} />
                          {event.agent_name || event.agent_id}
                        </span>
                      </td>
                      <td>
                        {event.actor ? (
                          <span className="name-cell">
                            <Avatar label={event.actor} size={20} />
                            {event.actor}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td>{event.action_type}</td>
                      <td className="resource-cell" title={event.resource}>
                        {event.resource}
                      </td>
                      <td>
                        <DecisionBadge decision={event.decision} />
                      </td>
                      <td>
                        {event.outcome ? (
                          <span className="name-cell" title={`${event.outcome.exec_ms} ms`}>
                            <DecisionBadge decision={event.outcome.status} />
                            <span className="muted">{event.outcome.exec_ms} ms</span>
                          </span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="split-detail">
              <div className="detail-panel">
                {!selectedEvent ? (
                  <div className="detail-placeholder">Select an event to see details.</div>
                ) : (
                  <>
                    <div className="detail-panel-header">
                      <span className="detail-panel-title">Event Details</span>
                      <button
                        type="button"
                        className="detail-panel-close"
                        onClick={() => setSelectedId(null)}
                        aria-label="Close details"
                      >
                        ✕
                      </button>
                    </div>
                    <div className="detail-panel-body">
                      <div className="detail-id-row">
                        <code>evt_{selectedEvent.id}</code>
                        <button
                          type="button"
                          className="id-copy"
                          onClick={() =>
                            copyText(`evt_${selectedEvent.id}`, () => {
                              setCopiedField("id");
                              setTimeout(() => setCopiedField(null), 1500);
                            })
                          }
                        >
                          <span>{copiedField === "id" ? "Copied" : "Copy"}</span>
                        </button>
                      </div>

                      <dl className="detail-grid">
                        <div>
                          <dt>Time</dt>
                          <dd>{new Date(selectedEvent.timestamp).toLocaleString()}</dd>
                        </div>
                        <div>
                          <dt>Decision</dt>
                          <dd>
                            <DecisionBadge decision={selectedEvent.decision} />
                          </dd>
                        </div>
                        <div>
                          <dt>Agent</dt>
                          <dd>{selectedEvent.agent_name || selectedEvent.agent_id}</dd>
                        </div>
                        <div>
                          <dt>Actor</dt>
                          <dd>{selectedEvent.actor || "—"}</dd>
                        </div>
                        <div>
                          <dt>Action type</dt>
                          <dd>{selectedEvent.action_type}</dd>
                        </div>
                        <div>
                          <dt>Decision latency</dt>
                          <dd title="Policy evaluation plus any approval wait">{selectedEvent.latency_ms} ms</dd>
                        </div>
                        <div>
                          <dt>Run</dt>
                          <dd className="mono">{selectedEvent.run_id || "—"}</dd>
                        </div>
                        <div>
                          <dt>Agent version</dt>
                          <dd>{selectedEvent.agent_version || "—"}</dd>
                        </div>
                        <div>
                          <dt>Policy</dt>
                          <dd className="mono">{selectedEvent.policy_hash || "—"}</dd>
                        </div>
                        <div>
                          <dt>Outcome</dt>
                          <dd>
                            {selectedEvent.outcome ? (
                              <span className="name-cell">
                                <DecisionBadge decision={selectedEvent.outcome.status} />
                                <span className="muted">{selectedEvent.outcome.exec_ms} ms</span>
                              </span>
                            ) : (
                              "not reported"
                            )}
                          </dd>
                        </div>
                      </dl>

                      <div className="detail-tabs">
                        <button
                          type="button"
                          className={"detail-tab" + (detailTab === "details" ? " active" : "")}
                          onClick={() => setDetailTab("details")}
                        >
                          Details
                        </button>
                        <button
                          type="button"
                          className={"detail-tab" + (detailTab === "raw" ? " active" : "")}
                          onClick={() => setDetailTab("raw")}
                        >
                          Raw JSON
                        </button>
                      </div>

                      {detailTab === "details" ? (
                        <dl className="detail-grid">
                          <div style={{ gridColumn: "1 / -1" }}>
                            <dt>Resource</dt>
                            <dd style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "0.78rem" }}>
                              {selectedEvent.resource}
                            </dd>
                          </div>
                          <div>
                            <dt>Matched rule</dt>
                            <dd>{selectedEvent.matched_rule || "—"}</dd>
                          </div>
                          <div>
                            <dt>Approval ID</dt>
                            <dd>{selectedEvent.approval_id || "—"}</dd>
                          </div>
                          <div style={{ gridColumn: "1 / -1" }}>
                            <dt>Reason</dt>
                            <dd>{selectedEvent.reason || "—"}</dd>
                          </div>
                          {selectedEvent.action?.args && Object.keys(selectedEvent.action.args).length > 0 && (
                            <div style={{ gridColumn: "1 / -1" }}>
                              <dt>Arguments</dt>
                              <dd>
                                <div className="code-block">
                                  <pre>{JSON.stringify(selectedEvent.action.args, null, 2)}</pre>
                                </div>
                              </dd>
                            </div>
                          )}
                          {selectedEvent.outcome?.error && (
                            <div style={{ gridColumn: "1 / -1" }}>
                              <dt>Error</dt>
                              <dd className="mono">{selectedEvent.outcome.error}</dd>
                            </div>
                          )}
                          {selectedEvent.outcome?.output && (
                            <div style={{ gridColumn: "1 / -1" }}>
                              <dt>
                                Output
                                {selectedEvent.outcome.output_bytes &&
                                selectedEvent.outcome.output_bytes > selectedEvent.outcome.output.length
                                  ? ` (first ${selectedEvent.outcome.output.length} of ${selectedEvent.outcome.output_bytes} bytes)`
                                  : ""}
                              </dt>
                              <dd>
                                <div className="code-block">
                                  <pre>{selectedEvent.outcome.output}</pre>
                                </div>
                              </dd>
                            </div>
                          )}
                        </dl>
                      ) : (
                        <div className="code-block">
                          <button
                            type="button"
                            className="code-block-copy"
                            onClick={() =>
                              copyText(JSON.stringify(selectedEvent, null, 2), () => {
                                setCopiedField("raw");
                                setTimeout(() => setCopiedField(null), 1500);
                              })
                            }
                          >
                            {copiedField === "raw" ? "Copied" : "Copy"}
                          </button>
                          <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
