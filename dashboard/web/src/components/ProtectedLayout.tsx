import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";

export function ProtectedLayout() {
  const { user, loading, currentTenantId, memberships } = useAuth();

  if (loading) {
    return <div className="page-center">Loading…</div>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-content">
        <Header />
        <main className="app-main">
          {memberships.length === 0 ? (
            <div className="empty-state">
              Your account isn't a member of any company yet.
            </div>
          ) : !currentTenantId ? (
            <div className="page-center">Loading…</div>
          ) : (
            <Outlet />
          )}
        </main>
      </div>
    </div>
  );
}
