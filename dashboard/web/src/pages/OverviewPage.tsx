import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { DecisionBadge } from "../components/DecisionBadge";
import { AgentStatusBadge, isAgentOnline } from "../components/AgentStatusBadge";
import { MiniStat } from "../components/MiniStat";
import { Sparkline } from "../components/Sparkline";
import { Avatar } from "../components/Avatar";
import { RankList } from "../components/RankList";
import { StatCard } from "../components/StatCard";
import { AnomalyList } from "../components/AnomalyList";
import { timeAgo } from "../lib/time";
import type { Agent, Anomaly, AuditEvent, Metrics } from "../api/types";

const HOUR_MS = 60 * 60 * 1000;

function emptyMetrics(): Metrics {
  return {
    allow_count: 0,
    deny_count: 0,
    require_approval_count: 0,
    top_denied_resources: null,
    top_denied_rules: null,
    total_count: 0,
    reported_count: 0,
    error_count: 0,
    distinct_resources: 0,
    by_action_type: null,
    top_resources: null,
    exec_p50_ms: null,
    exec_p95_ms: null,
    exec_samples: 0,
    events_per_hour: 0,
  };
}

function allowRate(m: Metrics): number | null {
  const total = m.allow_count + m.deny_count + m.require_approval_count;
  return total > 0 ? (m.allow_count / total) * 100 : null;
}

// Buckets events into `hours` one-hour-wide counts ending now — a real,
// client-computed trend line rather than a fabricated chart.
function bucketHourly(events: AuditEvent[], hours: number): number[] {
  const now = Date.now();
  const buckets = new Array(hours).fill(0) as number[];
  for (const e of events) {
    const t = new Date(e.timestamp).getTime();
    const hoursAgo = Math.floor((now - t) / HOUR_MS);
    const idx = hours - 1 - hoursAgo;
    if (idx >= 0 && idx < hours) buckets[idx] += 1;
  }
  return buckets;
}

export function OverviewPage() {
  const { currentTenantId, currentMembership } = useAuth();
  const isAdmin = currentMembership?.role === "admin";
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [ackError, setAckError] = useState<string | null>(null);

  const fetcher = useCallback(async () => {
    if (!currentTenantId) {
      return {
        rangeMetrics: emptyMetrics(),
        last24h: emptyMetrics(),
        prev24h: emptyMetrics(),
        agents: [] as Agent[],
        hourly: [] as AuditEvent[],
        recent: [] as AuditEvent[],
        anomalies: [] as Anomaly[],
      };
    }

    const now = new Date();
    const h24Ago = new Date(now.getTime() - 24 * HOUR_MS);
    const h48Ago = new Date(now.getTime() - 48 * HOUR_MS);

    const [rangeMetrics, last24h, prev24h, agentsResult, hourlyResult, recentResult, anomaliesResult] = await Promise.all([
      api.metrics(currentTenantId, {
        since: since ? new Date(since).toISOString() : undefined,
        until: until ? new Date(until).toISOString() : undefined,
      }),
      api.metrics(currentTenantId, { since: h24Ago.toISOString(), until: now.toISOString() }),
      api.metrics(currentTenantId, { since: h48Ago.toISOString(), until: h24Ago.toISOString() }),
      api.listAgents(currentTenantId),
      api.listEvents(currentTenantId, { since: h24Ago.toISOString(), limit: 500 }),
      api.listEvents(currentTenantId, { limit: 8 }),
      api.listAnomalies(currentTenantId, { unacknowledged: true }),
    ]);

    return {
      rangeMetrics,
      last24h,
      prev24h,
      agents: agentsResult.agents ?? [],
      hourly: hourlyResult.events ?? [],
      recent: recentResult.events ?? [],
      anomalies: (anomaliesResult.anomalies ?? []).slice(0, 8),
    };
  }, [currentTenantId, since, until]);

  const { data, error, loading, refetch } = usePolling(fetcher, 20_000, [
    currentTenantId,
    since,
    until,
  ]);

  const rangeMetrics = data?.rangeMetrics ?? emptyMetrics();
  const rangeTotal =
    rangeMetrics.allow_count + rangeMetrics.deny_count + rangeMetrics.require_approval_count;
  const agents = data?.agents ?? [];
  const onlineCount = agents.filter((a) => isAgentOnline(a.last_seen_at)).length;
  const pendingRegCount = agents.filter((a) => a.status === "pending").length;

  const currentRate = data ? allowRate(data.last24h) : null;
  const previousRate = data ? allowRate(data.prev24h) : null;
  const delta = currentRate !== null && previousRate !== null ? currentRate - previousRate : null;
  const hourlyVolume = data ? bucketHourly(data.hourly, 24) : [];
  const topRule = data?.last24h.top_denied_rules?.[0] ?? null;
  const isFiltered = Boolean(since || until);

  async function ackAnomaly(id: string) {
    if (!currentTenantId) return;
    setAckError(null);
    try {
      await api.ackAnomaly(currentTenantId, id);
      refetch();
    } catch (err) {
      setAckError(err instanceof Error ? err.message : "Failed to acknowledge anomaly.");
    }
  }

  const recentAgents = [...agents]
    .sort((a, b) => {
      const at = a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0;
      const bt = b.last_seen_at ? new Date(b.last_seen_at).getTime() : 0;
      return bt - at;
    })
    .slice(0, 5);

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-header-text">
          <h1>Overview</h1>
          <p className="page-subtitle">Fleet-wide policy activity, refreshed every 20s.</p>
        </div>
        <div className="filter-bar">
          <label>
            Since
            <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
          </label>
          <label>
            Until
            <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
          </label>
          <button type="button" className="btn-secondary" onClick={refetch}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="form-error">{error}</div>}

      {loading && !data ? (
        <div className="page-center">Loading…</div>
      ) : (
        <>
          <div className="hero-card">
            <div className="hero-main">
              <div className="hero-label">Allow rate · last 24h</div>
              <div className="hero-value-row">
                <span className="hero-value">{currentRate !== null ? `${currentRate.toFixed(1)}%` : "—"}</span>
                {delta !== null && (
                  <span className={"hero-trend " + (delta >= 0 ? "up" : "down")}>
                    {delta >= 0 ? "▲" : "▼"} {Math.abs(delta).toFixed(1)} pts vs. prior 24h
                  </span>
                )}
              </div>
              {topRule ? (
                <div className="hero-insight">
                  Most denials in the last 24h trace to <code>{topRule.value}</code> ({topRule.count})
                </div>
              ) : (
                <div className="hero-insight muted">No denials in the last 24 hours.</div>
              )}
              <div className="hero-actions">
                <Link to="/events" className="btn-secondary">
                  View Live Feed
                </Link>
                <Link to="/pending" className="btn-secondary">
                  Review Approvals
                </Link>
              </div>
            </div>
            <div className="hero-chart">
              <div className="hero-chart-label">Events / hour</div>
              <Sparkline points={hourlyVolume} />
            </div>
          </div>

          <div className="mini-stat-grid">
            <MiniStat label="Registered agents" value={agents.length} />
            <MiniStat label="Online now" value={onlineCount} />
            <MiniStat label="Awaiting registration" value={pendingRegCount} />
          </div>

          <div className="section-heading">
            {isFiltered ? "Decision breakdown · custom range" : "Decision breakdown · all time"}
          </div>
          <div className="stat-grid">
            <StatCard label="Allowed" value={rangeMetrics.allow_count} color="allow" total={rangeTotal} />
            <StatCard label="Denied" value={rangeMetrics.deny_count} color="deny" total={rangeTotal} />
            <StatCard
              label="Required approval"
              value={rangeMetrics.require_approval_count}
              color="approval"
              total={rangeTotal}
            />
          </div>

          <div className="rank-grid">
            <RankList title="Top denied resources" items={rangeMetrics.top_denied_resources} />
            <RankList title="Top denied rules" items={rangeMetrics.top_denied_rules} />
          </div>

          <div className="panel-grid">
            <div className="panel">
              <div className="panel-header">
                <h2>Fleet status</h2>
                <Link to="/agents" className="panel-link">
                  View all →
                </Link>
              </div>
              {recentAgents.length === 0 ? (
                <div className="empty-state small">No agents registered yet.</div>
              ) : (
                <table className="data-table compact">
                  <tbody>
                    {recentAgents.map((agent) => (
                      <tr key={agent.id}>
                        <td>
                          <span className="name-cell">
                            <Avatar label={agent.name} size={20} />
                            {agent.name}
                          </span>
                        </td>
                        <td>
                          <AgentStatusBadge lastSeenAt={agent.last_seen_at} />
                        </td>
                        <td
                          className="muted"
                          title={agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : undefined}
                        >
                          {agent.last_seen_at ? timeAgo(agent.last_seen_at) : "never"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            <div className="panel">
              <div className="panel-header">
                <h2>Recent activity</h2>
                <Link to="/events" className="panel-link">
                  View all →
                </Link>
              </div>
              {!data || data.recent.length === 0 ? (
                <div className="empty-state small">No activity yet.</div>
              ) : (
                <ul className="activity-list">
                  {data.recent.map((event) => (
                    <li key={event.id} className="activity-row">
                      <span className="activity-time" title={new Date(event.timestamp).toLocaleString()}>
                        {timeAgo(event.timestamp)}
                      </span>
                      <DecisionBadge decision={event.decision} />
                      <Avatar label={event.agent_name || event.agent_id} size={18} />
                      <span className="activity-agent">{event.agent_name || event.agent_id}</span>
                      <span className="activity-resource" title={event.resource}>
                        {event.resource}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="panel">
              <div className="panel-header">
                <h2>Anomalies</h2>
                <Link to="/settings" className="panel-link">
                  Tune thresholds →
                </Link>
              </div>
              {ackError && <div className="form-error">{ackError}</div>}
              <AnomalyList
                anomalies={data?.anomalies ?? []}
                showAgent
                isAdmin={isAdmin}
                onAck={ackAnomaly}
                emptyLabel="No unacknowledged anomalies."
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
