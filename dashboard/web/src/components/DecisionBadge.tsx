// Renders a policy decision ("allow" / "deny" / "require_approval") or an
// execution outcome ("success" / "error") as a colored pill. One component
// for both so the feed reads consistently: a successful run shares the
// "allow" tint, a failed one the "deny" tint.
export function DecisionBadge({ decision }: { decision: string }) {
  const cls =
    decision === "allow" || decision === "success"
      ? "badge badge-allow"
      : decision === "deny" || decision === "error"
        ? "badge badge-deny"
        : decision === "require_approval"
          ? "badge badge-approval"
          : "badge";
  return <span className={cls}>{decision}</span>;
}
