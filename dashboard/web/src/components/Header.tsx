import { useLocation } from "react-router-dom";

const PAGE_LABELS: Record<string, [string, string]> = {
  "/overview": ["Monitoring", "Overview"],
  "/events": ["Monitoring", "Live Feed"],
  "/pending": ["Monitoring", "Approvals"],
  "/agents": ["Fleet", "Agents"],
  "/settings": ["Configuration", "Settings"],
};

// Deliberately slim: identity, workspace switching, and logout all moved
// into the Sidebar. This bar is page context only.
export function Header() {
  const location = useLocation();
  const [section, page] = PAGE_LABELS[location.pathname] ?? ["", ""];

  return (
    <header className="app-topbar">
      <div className="breadcrumb">
        {section && <span className="breadcrumb-section">{section}</span>}
        {section && <span className="breadcrumb-sep">/</span>}
        {page && <span className="breadcrumb-page">{page}</span>}
      </div>
      <span className="live-pill">
        <span className="sidebar-status-dot" />
        Live
      </span>
    </header>
  );
}
