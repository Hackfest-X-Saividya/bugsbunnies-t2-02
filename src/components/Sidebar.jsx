import { useState } from "react";
import { Link, NavLink } from "react-router-dom";
import {
  Activity, ChevronLeft, FileClock, FileText, LayoutDashboard, Menu, ScanLine, Settings,
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
          <div className="profile-card">
            <div className="avatar">SG</div>
            <div className="profile-copy"><strong>Security workspace</strong><span>Free plan · Demo mode</span></div>
            <ChevronLeft size={16} className="profile-chevron" />
          </div>
        </div>
      </aside>
    </>
  );
}
