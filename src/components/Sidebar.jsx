import { useEffect, useRef, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import {
  Activity, ChevronDown, ChevronLeft, FileClock, FileText, LayoutDashboard, Menu, ScanLine, Settings,
  Shield, X, Waypoints,
} from "lucide-react";

const links = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan", label: "New Scan", icon: ScanLine },
  { to: "/history", label: "Scan History", icon: FileClock },
  { to: "/explorer", label: "API Explorer", icon: Waypoints },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const [open, setOpen] = useState(false);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const workspaceRef = useRef(null);

  useEffect(() => {
    const handlePointerDown = (event) => {
      if (workspaceRef.current && !workspaceRef.current.contains(event.target)) setWorkspaceOpen(false);
    };
    const handleKeyDown = (event) => {
      if (event.key === "Escape") setWorkspaceOpen(false);
    };
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  return (
    <>
      <button className="mobile-menu icon-button" aria-label="Open navigation menu" onClick={() => setOpen(true)}>
        <Menu size={19} />
      </button>
      {open && <button className="sidebar-backdrop" aria-label="Close navigation menu" onClick={() => setOpen(false)} />}
      <aside className={`sidebar ${open ? "sidebar-open" : ""}`}>
        <div className="brand-row">
          <Link to="/" className="brand" onClick={() => setOpen(false)}>
            <span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
            <span><strong>ShadowGuard</strong><small>AI SECURITY PLATFORM</small></span>
          </Link>
          <button className="icon-button mobile-close" aria-label="Close navigation menu" onClick={() => setOpen(false)}><X size={18} /></button>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="nav-links" aria-label="Main navigation">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} onClick={() => setOpen(false)} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
              <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
              {label === "New Scan" && <span className="nav-add">+</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><span className="status-dot" /><span>Analysis engine ready</span><Activity size={14} /></div>
          <div className="workspace-menu-wrap" ref={workspaceRef}>
          <button type="button" className="profile-card" aria-haspopup="dialog" aria-expanded={workspaceOpen} onClick={() => setWorkspaceOpen((current) => !current)}>
            <div className="avatar">SG</div>
            <div className="profile-copy"><strong>Security workspace</strong><span>Free plan · Demo mode</span></div>
            <ChevronDown size={16} className={`profile-chevron ${workspaceOpen ? "is-open" : ""}`} />
          </button>
          {workspaceOpen && <section className="workspace-popover" role="dialog" aria-label="Security workspace information">
            <div className="workspace-popover-heading"><div className="avatar">SG</div><div><strong>Security workspace</strong><span>Personal demo workspace</span></div></div>
            <div className="workspace-info-row"><span>Plan</span><strong>Free · Demo</strong></div>
            <div className="workspace-info-row"><span>Current scan</span><strong>Illustrative results</strong></div>
            <p>Workspace data shown here is local demo content. No account or live scan is connected.</p>
            <Link to="/settings" className="workspace-settings-link" onClick={() => { setWorkspaceOpen(false); setOpen(false); }}>Workspace settings <ChevronLeft size={14} /></Link>
            <button type="button" className="workspace-close" onClick={() => setWorkspaceOpen(false)}>Close</button>
          </section>}
          </div>
        </div>
      </aside>
    </>
  );
}
