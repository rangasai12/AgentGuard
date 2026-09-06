export function DecisionBadge({ decision }: { decision: string }) {
  const cls =
    decision === "allow"
      ? "badge badge-allow"
      : decision === "deny"
        ? "badge badge-deny"
        : decision === "require_approval"
          ? "badge badge-approval"
          : "badge";
  return <span className={cls}>{decision}</span>;
}
