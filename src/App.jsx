import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Bell, ChevronDown, Search, Shield } from "lucide-react";
import Sidebar from "./components/Sidebar.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import APIExplorer from "./pages/APIExplorer.jsx";
import EndpointDetails from "./pages/EndpointDetails.jsx";
import Reports from "./pages/Reports.jsx";
import ScanHistory from "./pages/ScanHistory.jsx";
import Settings from "./pages/Settings.jsx";
import LandingPage from "./pages/LandingPage.jsx";

const pageTitles = {
  "/dashboard": "Security overview",
  "/scan": "New analysis",
  "/history": "Scan history",
  "/explorer": "API surface",
  "/reports": "Reports & exports",
  "/settings": "Workspace settings",
};

function WorkspaceLayout() {
  const location = useLocation();
  const title = location.pathname.startsWith("/endpoints/") ? "Endpoint Risk X-Ray" : pageTitles[location.pathname] || "ShadowGuard AI";
  useEffect(() => { window.scrollTo({ top: 0, behavior: "instant" }); }, [location.pathname]);
  return <div className="app-shell">
    <Sidebar />
    <main className="main-area">
      <header className="topbar"><div className="topbar-title"><span className="breadcrumb-root"><Shield size={14} /> ShadowGuard</span><span className="breadcrumb-slash">/</span><strong>{title}</strong></div><div className="topbar-actions"><div className="topbar-search"><Search size={15} /><span>Search workspace</span><kbd>⌘ K</kbd></div><button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button><div className="workspace-switch"><span className="workspace-avatar">S</span><span>Demo workspace</span><ChevronDown size={14} /></div></div></header>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/explorer" element={<APIExplorer />} />
        <Route path="/endpoints/:id" element={<EndpointDetails />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </main>
  </div>;
}

export default function App() {
  return <Routes>
    <Route path="/" element={<LandingPage />} />
    <Route path="/*" element={<WorkspaceLayout />} />
  </Routes>;
}
