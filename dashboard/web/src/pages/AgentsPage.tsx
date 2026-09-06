import { useCallback, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { AgentStatusBadge, isAgentOnline } from "../components/AgentStatusBadge";
import { MiniStat } from "../components/MiniStat";
import { Avatar } from "../components/Avatar";
import { timeAgo } from "../lib/time";
import type { Agent } from "../api/types";

type SortKey = "name" | "status" | "last_seen_at" | "created_at";

export function AgentsPage() {
  const { currentTenantId, currentMembership } = useAuth();
  const isAdmin = currentMembership?.role === "admin";
  const [showAddModal, setShowAddModal] = useState(false);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [copiedId, setCopiedId] = useState<string | null>(null);

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
                  <th>Registration</th>
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
                  <tr key={agent.id}>
                    <td>
                      <span className="name-cell">
                        <Avatar label={agent.name} />
                        {agent.name}
                      </span>
                    </td>
                    <td>
                      <button type="button" className="id-copy" onClick={() => copyId(agent.id)} title={agent.id}>
                        <code>{agent.id.slice(0, 14)}…</code>
                        <span>{copiedId === agent.id ? "Copied" : "Copy"}</span>
                      </button>
                    </td>
                    <td>
                      <AgentStatusBadge lastSeenAt={agent.last_seen_at} />
                    </td>
                    <td className="muted">{agent.status}</td>
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
