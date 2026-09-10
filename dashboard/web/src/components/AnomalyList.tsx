import { timeAgo } from "../lib/time";
import type { Anomaly } from "../api/types";

// Kind badges reuse the existing decision-badge palette rather than
// inventing new colors: system/scope (a new footprint, or an outsized
// call) read as "deny"-severity, operation/volume (a mix or rate shift)
// as "approval"-severity.
const KIND_BADGE_CLASS: Record<Anomaly["kind"], string> = {
  system: "badge-deny",
  scope: "badge-deny",
  operation: "badge-approval",
  volume: "badge-approval",
};

function describeAnomaly(a: Anomaly): string {
  switch (a.key) {
    case "error_rate":
      return "elevated error rate";
    case "latency_p50":
      return "elevated execution time";
    case "deny_rate":
      return "elevated deny rate";
    case "events_per_hour":
      return "elevated call rate";
    case "calls_per_run":
      return "elevated calls per run";
    case "read":
    case "write":
    case "delete":
    case "permission":
      return `shift toward ${a.key}`;
    default:
      return a.kind === "system" ? `new footprint: ${a.key}` : a.key;
  }
}

interface AnomalyListProps {
  anomalies: Anomaly[];
  showAgent?: boolean;
  isAdmin?: boolean;
  onAck?: (id: string) => void;
  emptyLabel?: string;
}

export function AnomalyList({ anomalies, showAgent, isAdmin, onAck, emptyLabel }: AnomalyListProps) {
  if (anomalies.length === 0) {
    return <div className="empty-state small">{emptyLabel ?? "No anomalies detected."}</div>;
  }
  return (
    <ul className="anomaly-list">
      {anomalies.map((a) => (
        <li key={a.id} className="anomaly-row">
          <span className={"badge " + KIND_BADGE_CLASS[a.kind]}>{a.kind}</span>
          <span className="anomaly-desc">
            {describeAnomaly(a)}
            {showAgent && a.agent_name && <span className="muted"> · {a.agent_name}</span>}
            <span className="muted"> · v{a.agent_version}</span>
          </span>
          <span className="anomaly-time muted" title={new Date(a.detected_at).toLocaleString()}>
            {timeAgo(a.detected_at)}
          </span>
          {a.acknowledged_at ? (
            <span className="muted">Acknowledged</span>
          ) : (
            isAdmin &&
            onAck && (
              <button type="button" className="btn-secondary btn-ack" onClick={() => onAck(a.id)}>
                Ack
              </button>
            )
          )}
        </li>
      ))}
    </ul>
  );
}
