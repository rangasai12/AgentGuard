import { useCallback, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { AgentStatusBadge, isAgentOnline } from "../components/AgentStatusBadge";
import { MiniStat } from "../components/MiniStat";
import { Avatar } from "../components/Avatar";
import { RankList } from "../components/RankList";
import { AnomalyList } from "../components/AnomalyList";
import { timeAgo } from "../lib/time";
import type { Agent, Metrics, ToolCatalogEntry } from "../api/types";

type SortKey = "name" | "status" | "last_seen_at" | "created_at" | "last_agent_version";

export function AgentsPage() {
  const { currentTenantId, currentMembership } = useAuth();
  const isAdmin = currentMembership?.role === "admin";
  const [showAddModal, setShowAddModal] = useState(false);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const fetcher = useCallback(async () => {
    if (!currentTenantId) return { agents: [] as Agent[] };
    // The backend returns `{"agents":null}` (not `[]`) when there are none
    // — normalize here so every consumer below can just treat it as an array.
    const result = await api.listAgents(currentTenantId);
    return { agents: result.agents ?? [] };
  }, [currentTenantId]);

  // Light poll so last_seen_at / online status stays roughly fresh without
  // requiring a manual refresh.
  const { data, error, loading, refetch } = usePolling(fetcher, 10_000, [currentTenantId]);

  const agents = data?.agents ?? [];
  const onlineCount = agents.filter((a) => isAgentOnline(a.last_seen_at)).length;
  const pendingCount = agents.filter((a) => a.status === "pending").length;

  const visibleAgents = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = q ? agents.filter((a) => a.name.toLowerCase().includes(q)) : agents;
    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "status":
          cmp = a.status.localeCompare(b.status);
          break;
        case "last_seen_at":
          cmp =
            (a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0) -
            (b.last_seen_at ? new Date(b.last_seen_at).getTime() : 0);
          break;
        case "created_at":
          cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
          break;
        case "last_agent_version":
          cmp = (a.last_agent_version ?? "").localeCompare(b.last_agent_version ?? "");
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [agents, search, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  function sortArrow(key: SortKey) {
    if (key !== sortKey) return null;
    return <span className="sort-arrow">{sortDir === "asc" ? "▲" : "▼"}</span>;
  }

  async function copyId(id: string) {
    try {
      await navigator.clipboard.writeText(id);
      setCopiedId(id);
      setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 1500);
    } catch {
      // Clipboard API may be unavailable (e.g. insecure context); the id is
      // still visible in the row itself.
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-header-text">
          <h1>Fleet</h1>
          <p className="page-subtitle">Every agentguard-forwarder registered to this company.</p>
        </div>
        {isAdmin && (
          <button type="button" className="btn-primary" onClick={() => setShowAddModal(true)}>
            Add Agent
          </button>
        )}
      </div>

      {error && <div className="form-error">{error}</div>}

      {loading && !data ? (
        <div className="page-center">Loading…</div>
      ) : agents.length === 0 ? (
        <div className="empty-state">
          No agents registered yet.{" "}
          {isAdmin ? "Click “Add Agent” to register your first one." : ""}
        </div>
      ) : (
        <>
          <div className="mini-stat-grid">
            <MiniStat label="Total agents" value={agents.length} />
            <MiniStat label="Online now" value={onlineCount} />
            <MiniStat label="Awaiting registration" value={pendingCount} />
          </div>

          <div className="toolbar">
            <input
              type="text"
              className="search-input"
              placeholder="Search by name…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <span className="muted">
              {visibleAgents.length} of {agents.length} shown
            </span>
          </div>

          {visibleAgents.length === 0 ? (
            <div className="empty-state">No agents match “{search}”.</div>
          ) : (
            <div className="split-view">
              <div className="split-list">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th className="sortable" onClick={() => toggleSort("name")}>
                        Name {sortArrow("name")}
                      </th>
                      <th>Agent ID</th>
                      <th className="sortable" onClick={() => toggleSort("status")}>
                        Status {sortArrow("status")}
                      </th>
                      <th className="sortable" onClick={() => toggleSort("last_agent_version")}>
                        Version {sortArrow("last_agent_version")}
                      </th>
                      <th>Policy</th>
                      <th className="sortable" onClick={() => toggleSort("last_seen_at")}>
                        Last seen {sortArrow("last_seen_at")}
                      </th>
                      <th className="sortable" onClick={() => toggleSort("created_at")}>
                        Registered {sortArrow("created_at")}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleAgents.map((agent) => (
                      <tr
                        key={agent.id}
                        className={"clickable" + (agent.id === selectedId ? " selected" : "")}
                        onClick={() => setSelectedId(agent.id === selectedId ? null : agent.id)}
                      >
                        <td>
                          <span className="name-cell">
                            <Avatar label={agent.name} />
                            {agent.name}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="id-copy"
                            onClick={(e) => {
                              e.stopPropagation();
                              copyId(agent.id);
                            }}
                            title={agent.id}
                          >
                            <code>{agent.id.slice(0, 14)}…</code>
                            <span>{copiedId === agent.id ? "Copied" : "Copy"}</span>
                          </button>
                        </td>
                        <td>
                          <AgentStatusBadge lastSeenAt={agent.last_seen_at} />
                          {agent.status === "pending" && <span className="muted"> · pending</span>}
                        </td>
                        <td className="mono" title={agent.last_agent_version || undefined}>
                          {agent.last_agent_version ? shortVersion(agent.last_agent_version) : <span className="muted">—</span>}
                        </td>
                        <td className="mono" title={agent.last_policy_hash || undefined}>
                          {agent.last_policy_hash || <span className="muted">—</span>}
                        </td>
                        <td
                          className="muted"
                          title={agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : undefined}
                        >
                          {agent.last_seen_at ? timeAgo(agent.last_seen_at) : "never"}
                        </td>
                        <td className="muted" title={new Date(agent.created_at).toLocaleString()}>
                          {timeAgo(agent.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selectedId && currentTenantId && (
                <div className="split-detail wide">
                  {(() => {
                    const agent = agents.find((a) => a.id === selectedId);
                    return agent ? (
                      <AgentDetailPanel
                        tenantId={currentTenantId}
                        agent={agent}
                        isAdmin={isAdmin}
                        onClose={() => setSelectedId(null)}
                      />
                    ) : null;
                  })()}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {showAddModal && currentTenantId && (
        <AddAgentModal
          tenantId={currentTenantId}
          onClose={() => setShowAddModal(false)}
          onCreated={refetch}
        />
      )}
    </div>
  );
}

// Version tags can be long ("tools:9f8e7d6c5b4a", "git:0123456789ab"):
// keep the prefix and the first characters of the hash in a table cell.
function shortVersion(v: string): string {
  return v.length > 18 ? v.slice(0, 18) + "…" : v;
}

function fmt(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
}

function rate(num: number, den: number): number | null {
  return den > 0 ? (num / den) * 100 : null;
}

// AgentDetailPanel is the per-agent behavioral profile: what this agent
// does at the selected version, and how that differs from the previous
// version. Everything here is the same /api/metrics call the Overview page
// uses, scoped by agent_id and agent_version — there is no separate
// profile endpoint.
function AgentDetailPanel({
  tenantId,
  agent,
  isAdmin,
  onClose,
}: {
  tenantId: string;
  agent: Agent;
  isAdmin: boolean;
  onClose: () => void;
}) {
  // "" means all versions; otherwise one agent_version. Defaults to the
  // most recent version once the version list has loaded.
  const [version, setVersion] = useState<string | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);

  const fetcher = useCallback(async () => {
    const current = await api.metrics(tenantId, {
      agent_id: agent.id,
      agent_version: version ?? agent.last_agent_version ?? "",
    });
    const versions = current.versions ?? [];
    const selected = version ?? agent.last_agent_version ?? "";
    const idx = versions.findIndex((v) => v.agent_version === selected);
    const previousVersion = selected && idx >= 0 && idx + 1 < versions.length ? versions[idx + 1].agent_version : null;
    const [previous, toolsResult, anomaliesResult] = await Promise.all([
      previousVersion !== null ? api.metrics(tenantId, { agent_id: agent.id, agent_version: previousVersion }) : Promise.resolve(null),
      api.listTools(tenantId),
      api.listAnomalies(tenantId, { agent_id: agent.id }),
    ]);
    return { current, previous, previousVersion, tools: toolsResult.tools ?? [], selected, anomalies: anomaliesResult.anomalies ?? [] };
  }, [tenantId, agent.id, agent.last_agent_version, version]);

  const { data, error, loading, refetch } = usePolling(fetcher, 20_000, [tenantId, agent.id, version]);

  async function ackAnomaly(id: string) {
    setAckError(null);
    try {
      await api.ackAnomaly(tenantId, id);
      refetch();
    } catch (err) {
      setAckError(err instanceof Error ? err.message : "Failed to acknowledge anomaly.");
    }
  }

  const describe = useMemo(() => {
    const byKey = new Map<string, ToolCatalogEntry>();
    for (const t of data?.tools ?? []) byKey.set(`${t.action_type}:${t.resource}`, t);
    return (scopeKey: string) => {
      const t = byKey.get(scopeKey);
      if (!t) return undefined;
      const args = t.arg_keys.length ? ` (${t.arg_keys.join(", ")})` : "";
      return (t.description || t.resource) + args;
    };
  }, [data?.tools]);

  const m: Metrics | null = data?.current ?? null;
  const p: Metrics | null = data?.previous ?? null;

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <span className="detail-panel-title">
          <Avatar label={agent.name} size={18} />
          {agent.name}
        </span>
        <button type="button" className="detail-panel-close" onClick={onClose} aria-label="Close details">
          ✕
        </button>
      </div>
      <div className="detail-panel-body">
        {error && <div className="form-error">{error}</div>}
        {loading && !data ? (
          <div className="muted">Loading profile…</div>
        ) : !m ? null : (
          <>
            <label>
              Version
              <select className="version-select" value={data?.selected ?? ""} onChange={(e) => setVersion(e.target.value)}>
                <option value="">All versions ({fmt(m.versions?.reduce((n, v) => n + v.count, 0) ?? 0)} events)</option>
                {(m.versions ?? []).map((v) => (
                  <option key={v.agent_version} value={v.agent_version}>
                    {v.agent_version} · {fmt(v.count)} events · last {timeAgo(v.last_seen)}
                  </option>
                ))}
              </select>
            </label>

            {!m.versions?.length ? (
              <div className="empty-state small">No events from this agent yet.</div>
            ) : (
              <>
                <div className="detail-stat-grid">
                  <MiniStat label="Events" value={m.total_count} />
                  <MiniStat label="Denied" value={m.deny_count} />
                  <MiniStat label="Errors" value={m.error_count} />
                  <MiniStat label="Resources" value={m.distinct_resources} />
                  <MiniStat label="Events / hr" value={Math.round(m.events_per_hour * 10) / 10} />
                  <MiniStat label="p50 exec" value={m.exec_p50_ms === null ? 0 : Math.round(m.exec_p50_ms)} suffix="ms" />
                </div>

                <RankList title="By action type" items={m.by_action_type} compact />
                <RankList title="Footprint (top resources)" items={m.top_resources} describe={describe} compact />

                <div className="section-heading">Anomalies</div>
                {ackError && <div className="form-error">{ackError}</div>}
                <AnomalyList
                  anomalies={data?.anomalies ?? []}
                  isAdmin={isAdmin}
                  onAck={ackAnomaly}
                  emptyLabel="No anomalies detected for this agent."
                />

                {p && data?.previousVersion && (
                  <div>
                    <div className="section-heading">
                      {data.selected} vs. previous {data.previousVersion}
                    </div>
                    <table className="data-table compact delta-table">
                      <thead>
                        <tr>
                          <th>Metric</th>
                          <th>Current</th>
                          <th>Previous</th>
                          <th>Change</th>
                        </tr>
                      </thead>
                      <tbody>
                        <DeltaRow label="Events / hr" cur={m.events_per_hour} prev={p.events_per_hour} digits={1} />
                        <DeltaRow label="Deny rate %" cur={rate(m.deny_count, m.total_count)} prev={rate(p.deny_count, p.total_count)} digits={1} />
                        <DeltaRow label="Error rate %" cur={rate(m.error_count, m.reported_count)} prev={rate(p.error_count, p.reported_count)} digits={1} />
                        <DeltaRow label="p50 exec ms" cur={m.exec_p50_ms} prev={p.exec_p50_ms} />
                        <DeltaRow label="p95 exec ms" cur={m.exec_p95_ms} prev={p.exec_p95_ms} />
                        <DeltaRow label="Distinct resources" cur={m.distinct_resources} prev={p.distinct_resources} />
                        <DeltaRow
                          label="New resources"
                          cur={(m.top_resources ?? []).filter((r) => !(p.top_resources ?? []).some((q) => q.value === r.value)).length}
                          prev={null}
                        />
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function DeltaRow({ label, cur, prev, digits = 0 }: { label: string; cur: number | null; prev: number | null; digits?: number }) {
  let change: ReactNode = <span className="delta-flat">—</span>;
  if (cur !== null && prev !== null) {
    const d = cur - prev;
    const cls = Math.abs(d) < 1e-9 ? "delta-flat" : d > 0 ? "delta-up" : "delta-down";
    change = (
      <span className={cls}>
        {d > 0 ? "+" : ""}
        {fmt(d, digits)}
      </span>
    );
  }
  return (
    <tr>
      <td>{label}</td>
      <td>{fmt(cur, digits)}</td>
      <td>{fmt(prev, digits)}</td>
      <td>{change}</td>
    </tr>
  );
}

function AddAgentModal({
  tenantId,
  onClose,
  onCreated,
}: {
  tenantId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ agent_id: string; registration_token: string } | null>(
    null,
  );
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const created = await api.createAgent(tenantId, name.trim());
      setResult(created);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create agent.");
    } finally {
      setSubmitting(false);
    }
  }

  async function copyToken() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.registration_token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable (e.g. insecure context); the token
      // is still selectable/visible in the <code> block below.
    }
  }

  return (
    <div className="modal-backdrop" onClick={result ? undefined : onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        {!result ? (
          <form onSubmit={handleSubmit}>
            <h2>Add Agent</h2>
            {error && <div className="form-error">{error}</div>}
            <label>
              Agent name
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. prod-us-east-1"
                autoFocus
                required
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn-primary" disabled={submitting}>
                {submitting ? "Creating…" : "Create"}
              </button>
            </div>
          </form>
        ) : (
          <div>
            <h2>Agent registered</h2>
            <p className="warning-text">
              This registration token is shown only once — copy it now. You'll need it to set up
              the forwarder on the agent's machine.
            </p>
            <div className="token-box">
              <code>{result.registration_token}</code>
              <button type="button" className="btn-secondary" onClick={copyToken}>
                {copied ? "Copied!" : "Copy"}
              </button>
            </div>
            <p className="field-hint">Run this on the machine hosting the agent:</p>
            <div className="token-box">
              <code>agentguard-forwarder -register-token={result.registration_token}</code>
            </div>
            <div className="modal-actions">
              <button type="button" className="btn-primary" onClick={onClose}>
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
