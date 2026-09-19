import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Activity } from "./pages/Activity";
import { Approvals } from "./pages/Approvals";
import { Incidents } from "./pages/Incidents";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Reports } from "./pages/Reports";
import { Settings } from "./pages/Settings";
import { useSession } from "./lib/session";

function RequireAuth({ children }) {
  const { session } = useSession();
  if (!session) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/overview" element={<Overview />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
