import type { ResourceCount } from "../api/types";

// A ranked value/count list. Moved here from OverviewPage once the agent
// detail panel needed it too. `describe` supplies an optional tooltip per
// value (the agent panel passes tool descriptions from the catalog).
export function RankList({
  title,
  items,
  describe,
  compact,
}: {
  title: string;
  items: ResourceCount[] | null | undefined;
  describe?: (value: string) => string | undefined;
  compact?: boolean;
}) {
  return (
    <div className={"rank-list" + (compact ? " compact" : "")}>
      <h2>{title}</h2>
      {!items || items.length === 0 ? (
        <div className="empty-state small">No data yet.</div>
      ) : (
        <ol>
          {items.map((item) => (
            <li key={item.value}>
              <span className="rank-value" title={describe?.(item.value) ?? item.value}>
                {item.value}
              </span>
              <span className="rank-count">{item.count.toLocaleString()}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
