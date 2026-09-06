export function MiniStat({
  label,
  value,
  suffix,
}: {
  label: string;
  value: number;
  suffix?: string;
}) {
  return (
    <div className="mini-stat">
      <div className="mini-stat-value">
        {value.toLocaleString()}
        {suffix ? <span className="mini-stat-suffix"> {suffix}</span> : null}
      </div>
      <div className="mini-stat-label">{label}</div>
    </div>
  );
}
