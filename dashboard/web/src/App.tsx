import { Navigate, Route, Routes } from "react-router-dom";
import { ProtectedLayout } from "./components/ProtectedLayout";
import { LoginPage } from "./pages/LoginPage";
import { SignupPage } from "./pages/SignupPage";
import { AgentsPage } from "./pages/AgentsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { EventsPage } from "./pages/EventsPage";
import { PendingPage } from "./pages/PendingPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />

      <Route element={<ProtectedLayout />}>
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/pending" element={<PendingPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/" element={<Navigate to="/agents" replace />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
