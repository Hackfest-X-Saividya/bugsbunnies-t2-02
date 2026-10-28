import { ArrowRight, Clock3, ScanLine } from "lucide-react";
import { Link } from "react-router-dom";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader } from "../components/Primitives.jsx";

export default function ScanHistory() {
  const { scan } = useScan();
  return <div className="page-content">
    <PageHeader eyebrow="WORKSPACE / ACTIVITY" title="Scan history" description="Review the analysis currently loaded in this workspace." action={<Link to="/scan" className="button button-primary"><ScanLine size={15} /> New scan</Link>} />
    {scan.isDemo && <DemoNotice />}
    <section className="panel history-panel"><div className="panel-heading"><div><h2>Recent analyses</h2><p>Scan history is local to this active session in demo mode.</p></div><span className="panel-kicker">{scan.isDemo ? "DEMO" : "LIVE"}</span></div>
      <div className="history-row"><div className="history-icon"><ScanLine size={18} /></div><div className="history-project"><strong>{scan.projectName}</strong><span>{scan.id} · {scan.findings.length} findings · {scan.endpoints.length} routes</span></div><span className="history-status"><i />{scan.status}</span><div className="history-time"><Clock3 size={14} /> Just now</div><Link to="/dashboard" className="table-action" aria-label="Open scan dashboard"><ArrowRight size={16} /></Link></div>
    </section>
    <div className="history-placeholder"><Clock3 size={20} /><strong>More scan history appears here</strong><p>Completed scans from your backend can be connected here when the history API is available.</p></div>
  </div>;
}
