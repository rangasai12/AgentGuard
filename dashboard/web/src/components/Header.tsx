import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const PAGE_LABELS: Record<string, [string, string]> = {
  "/overview": ["Monitoring", "Overview"],
  "/events": ["Monitoring", "Live Feed"],
  "/pending": ["Monitoring", "Approvals"],
  "/agents": ["Fleet", "Agents"],
  "/settings": ["Configuration", "Settings"],
};

export function Header() {
  const { user, memberships, currentTenantId, setCurrentTenantId, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  const [section, page] = PAGE_LABELS[location.pathname] ?? ["", ""];
  const initial = user?.email ? user.email[0].toUpperCase() : "?";

  return (
    <header className="app-topbar">
      <div className="breadcrumb">
        {section && <span className="breadcrumb-section">{section}</span>}
        {section && <span className="breadcrumb-sep">/</span>}
        {page && <span className="breadcrumb-page">{page}</span>}
      </div>
      <div className="app-topbar-right">
        <span className="live-pill">
          <span className="sidebar-status-dot" />
          Live
        </span>
        {memberships.length > 1 ? (
          <select
            aria-label="Switch tenant"
            className="tenant-select"
            value={currentTenantId ?? ""}
            onChange={(e) => setCurrentTenantId(e.target.value)}
          >
            {memberships.map((m) => (
              <option key={m.tenant_id} value={m.tenant_id}>
                {m.tenant_name} ({m.role})
              </option>
            ))}
          </select>
        ) : memberships.length === 1 ? (
          <span className="tenant-name">{memberships[0].tenant_name}</span>
        ) : (
          <span />
        )}
        {user && (
          <div className="user-chip">
            <span className="user-avatar">{initial}</span>
            <span className="user-email">{user.email}</span>
          </div>
        )}
        <button type="button" className="btn-link" onClick={handleLogout}>
          Log out
        </button>
      </div>
    </header>
  );
}
