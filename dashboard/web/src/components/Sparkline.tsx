// A tiny inline area/line chart for a series of real counts (e.g. events
// per hour). No charting library — this is the one shape this UI needs.
export function Sparkline({ points, color = "var(--accent)" }: { points: number[]; color?: string }) {
  if (points.length < 2 || points.every((p) => p === 0)) {
    return <div className="sparkline-empty">Not enough activity yet to chart</div>;
  }

  const w = 100;
  const h = 32;
  const pad = 2;
  const max = Math.max(...points);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const stepX = (w - pad * 2) / (points.length - 1);

  const coords = points.map((p, i) => {
    const x = pad + i * stepX;
    const y = h - pad - ((p - min) / range) * (h - pad * 2);
    return [x, y] as const;
  });

  const linePath = coords.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  const areaPath = `${linePath} L${coords[coords.length - 1][0].toFixed(2)},${h - pad} L${coords[0][0].toFixed(2)},${h - pad} Z`;

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="sparkline" preserveAspectRatio="none">
      <path d={areaPath} fill={color} opacity={0.14} stroke="none" />
      <path d={linePath} fill="none" stroke={color} strokeWidth={1.6} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
