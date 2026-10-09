import { NavLink, useNavigate } from "react-router-dom";
import { useCallback } from "react";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "../hooks/usePolling";
import { api } from "../api/client";
import { IconOverview, IconFleet, IconFeed, IconApprovals, IconSettings } from "./icons";

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
  {
    label: "Configuration",
    items: [{ to: "/settings", label: "Settings", icon: IconSettings }],
  },
];

// Identity (workspace switcher, user, connectivity) lives in the sidebar
// now, not the topbar — the topbar is just page context (breadcrumb).
export function Sidebar() {
  const { user, memberships, currentTenantId, currentMembership, setCurrentTenantId, logout } = useAuth();
  const navigate = useNavigate();

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

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  const initial = user?.email ? user.email[0].toUpperCase() : "?";

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark" />
        AgentGuard
      </div>

      <div className="sidebar-workspace">
        <div className="workspace-label">Workspace</div>
        {memberships.length > 1 ? (
          <select
            aria-label="Switch tenant"
            className="workspace-select"
            value={currentTenantId ?? ""}
            onChange={(e) => setCurrentTenantId(e.target.value)}
          >
            {memberships.map((m) => (
              <option key={m.tenant_id} value={m.tenant_id}>
                {m.tenant_name}
              </option>
            ))}
          </select>
        ) : (
          <div className="workspace-name">{memberships[0]?.tenant_name ?? "—"}</div>
        )}
        {currentMembership && <div className="workspace-role">{currentMembership.role}</div>}
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
        <div className="sidebar-user">
          <span className="user-avatar">{initial}</span>
          <div className="sidebar-user-text">
            <span className="user-email" title={user?.email}>
              {user?.email}
            </span>
            <span className="connection-status">
              <span className={"sidebar-status-dot" + (connectionError ? " down" : "")} />
              {connectionError ? "Connection issue" : "All systems live"}
            </span>
          </div>
        </div>
        <button type="button" className="btn-link sidebar-logout" onClick={handleLogout}>
          Log out
        </button>
      </div>
    </aside>
  );
}
