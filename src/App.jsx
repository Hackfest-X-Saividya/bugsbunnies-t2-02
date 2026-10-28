import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft, Bell, Braces, Check, ChevronDown, CircleUserRound, FileClock,
  FileText, LayoutDashboard, LogOut, Search, Settings as SettingsIcon, Shield, X,
} from "lucide-react";
import Sidebar from "./components/Sidebar.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import APIExplorer from "./pages/APIExplorer.jsx";
import EndpointDetails from "./pages/EndpointDetails.jsx";
import Reports from "./pages/Reports.jsx";
import ScanHistory from "./pages/ScanHistory.jsx";
import Settings from "./pages/Settings.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import { useScan } from "./context/ScanContext.jsx";

const pageTitles = {
  "/dashboard": "Security overview",
  "/scan": "New analysis",
  "/history": "Scan history",
  "/explorer": "API surface",
  "/reports": "Reports & exports",
  "/settings": "Workspace settings",
};

const searchablePages = [
  { title: "Dashboard", detail: "Security posture and recent findings", path: "/dashboard", type: "Page", icon: LayoutDashboard },
  { title: "New Scan", detail: "Upload a project or load a sample", path: "/scan", type: "Page", icon: Shield },
  { title: "Scan History", detail: "Recent project analyses", path: "/history", type: "Page", icon: FileClock },
  { title: "API Explorer", detail: "Discovered routes and documentation", path: "/explorer", type: "Page", icon: Braces },
  { title: "Reports", detail: "Review and export findings", path: "/reports", type: "Page", icon: FileText },
  { title: "Settings", detail: "Workspace and backend configuration", path: "/settings", type: "Page", icon: SettingsIcon },
];

const initialNotifications = [
  { id: "finding", title: "High-severity signals need review", detail: "2 potential findings are marked High in the demo scan.", read: false, path: "/dashboard" },
  { id: "docs", title: "Documentation mismatch detected", detail: "One discovered route is not documented.", read: false, path: "/explorer" },
  { id: "scan", title: "Demo analysis is ready", detail: "payments-api has 5 illustrative findings and 5 routes.", read: true, path: "/history" },
];

function WorkspaceLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { scan } = useScan();
  const [activePanel, setActivePanel] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [notifications, setNotifications] = useState(initialNotifications);
  const [profileDetailsOpen, setProfileDetailsOpen] = useState(false);
  const [notice, setNotice] = useState(location.state?.demoMessage || "");
  const [noticeKey, setNoticeKey] = useState(0);
  const headerRef = useRef(null);
  const searchInputRef = useRef(null);
  const searchTriggerRef = useRef(null);
  const title = location.pathname.startsWith("/endpoints/") ? "Endpoint Risk X-Ray" : pageTitles[location.pathname] || "ShadowGuard AI";
  const unreadCount = notifications.filter((notification) => !notification.read).length;
  const results = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return searchablePages;
    const matches = (value) => value?.toLowerCase().includes(query);
    const pageResults = searchablePages.filter((item) => matches(item.title) || matches(item.detail)).map((item) => ({ ...item, key: `page-${item.path}` }));
    const findingResults = scan.findings.filter((item) => matches(item.title) || matches(item.id) || matches(item.description) || matches(item.filePath))
      .map((item) => ({
        title: item.title,
        detail: `${item.id} · ${item.severity} · ${item.filePath}:${item.line}`,
        path: item.endpointId ? `/endpoints/${item.endpointId}` : "/reports",
        type: "Finding",
        icon: Shield,
        key: `finding-${item.id}`,
      }));
    const endpointResults = scan.endpoints.filter((item) => matches(item.path) || matches(item.method) || matches(item.filePath) || matches(item.summary))
      .map((item) => ({
        title: `${item.method} ${item.path}`,
        detail: `${item.filePath} · ${item.documented ? "Documented" : "Documentation mismatch"}`,
        path: `/endpoints/${item.id}`,
        type: "Endpoint",
        icon: Braces,
        key: `endpoint-${item.id}`,
      }));
    return [...pageResults, ...findingResults, ...endpointResults].slice(0, 12);
  }, [scan, searchQuery]);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" });
    setActivePanel(null);
    setProfileDetailsOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (location.state?.demoMessage) {
      setNotice(location.state.demoMessage);
      setNoticeKey((current) => current + 1);
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location.pathname, location.state, navigate]);

  useEffect(() => {
    if (!notice) return undefined;
    const timer = window.setTimeout(() => setNotice(""), 6000);
    return () => window.clearTimeout(timer);
  }, [notice, noticeKey]);

  useEffect(() => {
    if (activePanel === "search") searchInputRef.current?.focus();
  }, [activePanel]);

  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        const searchHasFocus = searchInputRef.current?.closest(".search-panel")?.contains(document.activeElement);
        setActivePanel(null);
        setProfileDetailsOpen(false);
        if (searchHasFocus) searchTriggerRef.current?.focus();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setActivePanel((current) => current === "search" ? null : "search");
      }
    };
    const handlePointerDown = (event) => {
      if (headerRef.current && !headerRef.current.contains(event.target)) setActivePanel(null);
    };
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, []);

  const openSearch = () => {
    setActivePanel((current) => current === "search" ? null : "search");
    setProfileDetailsOpen(false);
  };
  const selectSearchResult = (path) => {
    setActivePanel(null);
    setSearchQuery("");
    navigate(path);
  };
  const markAllRead = () => setNotifications((items) => items.map((item) => ({ ...item, read: true })));
  const dismissNotification = (id) => setNotifications((items) => items.filter((item) => item.id !== id));
  const handleSignOut = () => {
    setActivePanel(null);
    navigate("/", { state: { demoMessage: "You signed out of the demo workspace. No account session was active." } });
  };

  return <div className="app-shell">
    <Sidebar />
    <main className="main-area">
      <header className="topbar">
        <div className="topbar-title"><span className="breadcrumb-root"><Shield size={14} /> ShadowGuard</span><span className="breadcrumb-slash">/</span><strong>{title}</strong></div>
        <div className="topbar-actions" ref={headerRef}>
          <div className="header-control search-control">
            <button ref={searchTriggerRef} type="button" className="topbar-search" aria-label="Search workspace" aria-haspopup="dialog" aria-expanded={activePanel === "search"} aria-controls="workspace-search-panel" onClick={openSearch}>
              <Search size={15} /><span>Search workspace</span><kbd>⌘ K</kbd>
            </button>
            {activePanel === "search" && <div id="workspace-search-panel" className="search-panel" role="dialog" aria-label="Search workspace">
              <div className="search-panel-input"><Search size={16} /><input ref={searchInputRef} value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Search pages, findings, endpoints…" aria-label="Search pages, demo vulnerabilities, and API endpoints" /><kbd>ESC</kbd><button type="button" className="popover-icon-button" aria-label="Close search" onClick={() => { setActivePanel(null); searchTriggerRef.current?.focus(); }}><X size={15} /></button></div>
              <div className="search-results" aria-label="Search results">
                {results.length ? results.map((item) => {
                  const Icon = item.icon;
                  return <button type="button" className="search-result" key={item.key || item.path} onClick={() => selectSearchResult(item.path)}>
                    <span className="search-result-icon"><Icon size={15} /></span><span className="search-result-copy"><strong>{item.title}</strong><small>{item.detail}</small></span><span className="search-result-type">{item.type}</span>
                  </button>;
                }) : <div className="search-empty">No pages, findings, or endpoints match “{searchQuery}”.</div>}
              </div>
              <div className="search-panel-footer">Search this workspace <span>ESC to close</span></div>
            </div>}
          </div>
          <div className="header-control">
            <button type="button" className="icon-button notification-button" aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ""}`} aria-haspopup="dialog" aria-expanded={activePanel === "notifications"} onClick={() => setActivePanel((current) => current === "notifications" ? null : "notifications")}>
              <Bell size={17} />{unreadCount > 0 && <i aria-hidden="true" />}
            </button>
            {activePanel === "notifications" && <section className="header-popover notification-popover" role="dialog" aria-label="Demo notifications">
              <div className="popover-heading"><div><strong>Notifications</strong><small>Demo activity · not live alerts</small></div><button type="button" className="popover-icon-button" aria-label="Close notifications" onClick={() => setActivePanel(null)}><X size={15} /></button></div>
              {unreadCount > 0 && <button type="button" className="mark-read-button" onClick={markAllRead}><Check size={13} /> Mark all as read</button>}
              <div className="notification-list">
                {notifications.length ? notifications.map((item) => <article className={`notification-item ${item.read ? "is-read" : ""}`} key={item.id}>
                  <button type="button" className="notification-content" onClick={() => { setNotifications((items) => items.map((notification) => notification.id === item.id ? { ...notification, read: true } : notification)); selectSearchResult(item.path); }}>
                    <span className="notification-indicator">{!item.read && <i />}</span><span><strong>{item.title}</strong><small>{item.detail}</small><em>Demo notification</em></span>
                  </button>
                  <button type="button" className="popover-icon-button dismiss-notification" aria-label={`Dismiss ${item.title}`} onClick={() => dismissNotification(item.id)}><X size={14} /></button>
                </article>) : <div className="search-empty">You’ve dismissed all demo notifications.</div>}
              </div>
              <div className="popover-footer">Notifications are illustrative demo data.</div>
            </section>}
          </div>
          <div className="header-control profile-control">
            <button type="button" className="workspace-switch" aria-label="Demo workspace profile menu" aria-haspopup="dialog" aria-expanded={activePanel === "profile"} onClick={() => { setActivePanel((current) => current === "profile" ? null : "profile"); setProfileDetailsOpen(false); }}>
              <span className="workspace-avatar">S</span><span>Demo workspace</span><ChevronDown size={14} />
            </button>
            {activePanel === "profile" && <section className="header-popover profile-popover" role="dialog" aria-label="Demo profile menu">
              {profileDetailsOpen ? <>
                <div className="popover-heading"><button type="button" className="popover-icon-button" aria-label="Back to profile menu" onClick={() => setProfileDetailsOpen(false)}><ArrowLeft size={15} /></button><div><strong>Demo profile</strong><small>Profile details</small></div><button type="button" className="popover-icon-button" aria-label="Close profile menu" onClick={() => setActivePanel(null)}><X size={15} /></button></div>
                <div className="profile-details"><span className="profile-detail-avatar">SG</span><strong>Security workspace</strong><small>Demo profile · no account connected</small><span className="demo-profile-note">This frontend demo does not sign in to a real user account.</span></div>
              </> : <>
                <div className="profile-menu-heading"><span className="profile-detail-avatar">SG</span><div><strong>Demo workspace</strong><small>Demo profile · no account</small></div></div>
                <div className="profile-menu-actions" aria-label="Profile actions">
                  <button type="button" onClick={() => setProfileDetailsOpen(true)}><CircleUserRound size={15} /> Profile</button>
                  <button type="button" onClick={() => { setActivePanel(null); navigate("/settings"); }}><SettingsIcon size={15} /> Settings</button>
                  <button type="button" className="signout-action" onClick={handleSignOut}><LogOut size={15} /> Sign out of demo</button>
                </div>
                <div className="popover-footer">No real account is signed in.</div>
              </>}
            </section>}
          </div>
        </div>
      </header>
      {notice && <div key={noticeKey} className="demo-session-message dismissible-notice" role="status"><Shield size={14} /><span>{notice}</span><button type="button" aria-label="Dismiss message" onClick={() => setNotice("")}><X size={14} /></button></div>}
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
