// Deterministic color from a name so the same agent/actor always renders
// the same avatar color across the app — purely decorative, no identity
// system behind it.
function hashHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 360;
}

export function Avatar({ label, size = 22 }: { label: string; size?: number }) {
  const safe = label || "?";
  const hue = hashHue(safe);
  return (
    <span
      className="avatar-dot"
      style={{
        width: size,
        height: size,
        fontSize: Math.round(size * 0.45),
        background: `hsl(${hue}, 55%, 42%)`,
      }}
    >
      {safe[0].toUpperCase()}
    </span>
  );
}
