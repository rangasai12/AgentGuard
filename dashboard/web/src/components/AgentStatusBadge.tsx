const ONLINE_WINDOW_MS = 60_000;

// "Online" is derived client-side from last_seen_at freshness, since the
// backend only tracks a coarse pending/active `status` — per spec, there's
// no explicit online/offline field.
export function isAgentOnline(lastSeenAt: string | null | undefined, now = Date.now()): boolean {
  if (!lastSeenAt) return false;
  const seenAt = new Date(lastSeenAt).getTime();
  if (Number.isNaN(seenAt)) return false;
  return now - seenAt <= ONLINE_WINDOW_MS;
}

export function AgentStatusBadge({ lastSeenAt }: { lastSeenAt: string | null | undefined }) {
  const online = isAgentOnline(lastSeenAt);
  return (
    <span className={`badge ${online ? "badge-online" : "badge-offline"}`}>
      <span className="dot" />
      {online ? "online" : "offline"}
    </span>
  );
}
