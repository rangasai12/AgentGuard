import { NavLink } from "react-router-dom";
import { useCallback } from "react";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { api } from "../api/client";
import { IconOverview, IconFleet, IconFeed, IconApprovals } from "./icons";

const NAV_GROUPS = [
  {
    label: "Monitoring",
    items: [
      { to: "/overview", label: "Overview", icon: IconOverview },
      { to: "/events", label: "Live Feed", icon: IconFeed },
      { to: "/pending", label: "Approvals", icon: IconApprovals, badge: true },
    ],
  },
  {
    label: "Fleet",
    items: [{ to: "/agents", label: "Agents", icon: IconFleet }],
  },
];

export function Sidebar() {
  const { currentTenantId } = useAuth();

  // Doubles as a real connectivity probe for the footer status line below —
  // this isn't decorative polling, it's the same call the Approvals page
  // makes, so its success/failure is a genuine signal.
  const fetchPendingCount = useCallback(async () => {
    if (!currentTenantId) return 0;
    const result = await api.listPending(currentTenantId);
    return (result.pending ?? []).length;
  }, [currentTenantId]);

  const { data: pendingCount, error: connectionError } = usePolling(fetchPendingCount, 8_000, [
    currentTenantId,
  ]);

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark" />
        AgentGuard
      </div>
      <nav className="sidebar-nav">
        {NAV_GROUPS.map((group) => (
          <div className="sidebar-group" key={group.label}>
            <div className="sidebar-group-label">{group.label}</div>
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => "sidebar-link" + (isActive ? " active" : "")}
                >
                  <span className="sidebar-link-main">
                    <Icon className="sidebar-icon" />
                    {item.label}
                  </span>
                  {item.badge && !!pendingCount && <span className="sidebar-badge">{pendingCount}</span>}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span className={"sidebar-status-dot" + (connectionError ? " down" : "")} />
        {connectionError ? "Connection issue" : "All systems live"}
      </div>
    </aside>
  );
}
