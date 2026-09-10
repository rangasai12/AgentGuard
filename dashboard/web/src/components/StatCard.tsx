// A decision-count card with a share bar. Moved here from OverviewPage
// once the agent detail panel needed the same card; both pages import it.
export function StatCard({
  label,
  value,
  color,
  total,
}: {
  label: string;
  value: number;
  color: "allow" | "deny" | "approval";
  total: number;
}) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className={`stat-card stat-${color}`}>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
      <div className="stat-bar-track">
        <div className="stat-bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="stat-pct">{pct}%</div>
    </div>
  );
}
