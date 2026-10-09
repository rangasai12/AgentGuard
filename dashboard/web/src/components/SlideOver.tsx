import type { ReactNode } from "react";

// Shared right-side drawer shell for row detail views (Live Feed, Fleet).
// Each page still renders its own .detail-panel content inside this —
// only the backdrop/positioning is common.
export function SlideOver({
  open,
  onClose,
  children,
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="slide-over-backdrop" onClick={onClose}>
      <div className="slide-over" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}
