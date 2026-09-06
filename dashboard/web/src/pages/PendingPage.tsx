import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { timeAgo } from "../lib/time";
import type { Agent, PendingApproval } from "../api/types";

const POLL_INTERVAL_MS = 2_000;
const URGENT_AFTER_MS = 60_000;

export function PendingPage() {
  const { currentTenantId, currentMembership } = useAuth();
  const isAdmin = currentMembership?.role === "admin";
  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentFilter, setAgentFilter] = useState("");

  useEffect(() => {
    if (!currentTenantId) return;
    api.listAgents(currentTenantId).then((r) => setAgents(r.agents ?? [])).catch(() => {});
  }, [currentTenantId]);

  const fetcher = useCallback(async () => {
    if (!currentTenantId) return { pending: [] as PendingApproval[] };
    const result = await api.listPending(currentTenantId);
    // Backend returns `{"pending":null}` when there's nothing waiting.
    return { pending: result.pending ?? [] };
  }, [currentTenantId]);

  const { data, error, loading, refetch } = usePolling(fetcher, POLL_INTERVAL_MS, [
    currentTenantId,
  ]);

  // Optimistic "relaying to agent..." tracking: the resolve endpoint
  // returns 200 immediately but the row stays status="pending" (with
  // requested_resolution set) until the forwarder actually relays it to
  // the local daemon (~2s). We track in-flight requests locally so the
  // button disables the instant it's clicked, not just once the next poll
  // reflects requested_resolution from the server.
  const [inFlight, setInFlight] = useState<Record<string, "approve" | "deny">>({});
  const [actionError, setActionError] = useState<string | null>(null);

  async function resolve(pendingId: string, resolution: "approve" | "deny") {
    if (!currentTenantId) return;
    setActionError(null);
    setInFlight((prev) => ({ ...prev, [pendingId]: resolution }));
    try {
      await api.resolvePending(currentTenantId, pendingId, resolution);
      refetch();
    } catch (err) {
      setInFlight((prev) => {
        const next = { ...prev };
        delete next[pendingId];
        return next;
      });
      setActionError(err instanceof ApiError ? err.message : "Failed to resolve approval.");
    }
  }

  const allPending = data?.pending ?? [];
  const pending = agentFilter ? allPending.filter((p) => p.agent_id === agentFilter) : allPending;

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-header-text">
          <h1>
            Pending Approvals
            {allPending.length > 0 && <span className="count-chip">{allPending.length}</span>}
          </h1>
          <p className="page-subtitle">Actions waiting on a human decision, polled every 2s.</p>
        </div>
        {agents.length > 1 && (
          <select
            className="search-input"
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            aria-label="Filter by agent"
          >
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {error && <div className="form-error">{error}</div>}
      {actionError && <div className="form-error">{actionError}</div>}

      {loading && !data ? (
        <div className="page-center">Loading…</div>
      ) : pending.length === 0 ? (
        <div className="empty-state">
          {allPending.length === 0
            ? "Nothing waiting on human approval right now."
            : "No pending approvals for this agent."}
        </div>
      ) : (
        <ul className="approval-list">
          {pending.map((item) => {
            const resolution = item.requested_resolution || inFlight[item.id];
            const urgent = Date.now() - new Date(item.created_at).getTime() > URGENT_AFTER_MS;
            return (
              <li key={item.id} className={"approval-card" + (urgent ? " urgent" : "")}>
                <div className="approval-main">
                  <div className="approval-title">
                    <strong>{item.action_type}</strong>
                    <span className="muted"> on </span>
                    <code>{item.resource}</code>
                  </div>
                  <div className="approval-meta">
                    Agent: {item.agent_name || item.agent_id} · Actor: {item.actor || "—"} · Waiting{" "}
                    <span title={new Date(item.created_at).toLocaleString()}>{timeAgo(item.created_at)}</span>
                  </div>
                  {item.matched_rule && (
                    <div className="approval-meta">Matched rule: {item.matched_rule}</div>
                  )}
                  {item.reason && <div className="approval-meta">Reason: {item.reason}</div>}
                </div>
                <div className="approval-actions">
                  {resolution ? (
                    <span className="badge badge-relaying">
                      Relaying {resolution === "approve" ? "approval" : "denial"} to agent…
                    </span>
                  ) : (
                    isAdmin && (
                      <>
                        <button
                          type="button"
                          className="btn-approve"
                          onClick={() => resolve(item.id, "approve")}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="btn-deny"
                          onClick={() => resolve(item.id, "deny")}
                        >
                          Deny
                        </button>
                      </>
                    )
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
