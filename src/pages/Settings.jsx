import { useState } from "react";
import { Check, ExternalLink, Shield, SlidersHorizontal } from "lucide-react";
import { PageHeader, ScanStatusNotice } from "../components/Primitives.jsx";
import { isDemoMode } from "../services/api.js";

export default function Settings() {
  const [saved, setSaved] = useState(false);
  return <div className="page-content">
    <PageHeader eyebrow="WORKSPACE / PREFERENCES" title="Settings" description="Workspace status and frontend integration configuration." />
    {isDemoMode && <ScanStatusNotice>Backend is not configured. Live scans are unavailable; sample projects are illustrative only.</ScanStatusNotice>}
    <section className="panel settings-panel"><div className="panel-heading"><div><h2>Backend connection</h2><p>Live analysis is controlled by the app environment, not stored in the browser.</p></div><div className={`connection-pill ${isDemoMode ? "connection-demo" : "connection-live"}`}><span />{isDemoMode ? "Demo mode" : "Backend configured"}</div></div>
      <div className="settings-row"><div className="settings-icon"><SlidersHorizontal size={17} /></div><div><strong>API base URL</strong><p>Set <code>VITE_API_BASE_URL</code> in your local <code>.env</code> file, then restart Vite to enable live API requests.</p></div><span className="settings-value">{isDemoMode ? "Not configured" : "Configured"}</span></div>
      <div className="settings-row"><div className="settings-icon"><Shield size={17} /></div><div><strong>Privacy & source handling</strong><p>Uploaded files are only sent to the configured backend when live mode is enabled. The browser does not execute source code.</p></div><span className="settings-value">Frontend safeguards active</span></div>
      <div className="settings-hint"><ExternalLink size={15} /> API request and response handling is centralized in <code>src/services/api.js</code>.</div>
      <button className="button button-outline" onClick={() => { setSaved(true); window.setTimeout(() => setSaved(false), 1800); }}>{saved ? <Check size={15} /> : <SlidersHorizontal size={15} />}{saved ? "Settings reviewed" : "Mark settings reviewed"}</button>
    </section>
  </div>;
}
