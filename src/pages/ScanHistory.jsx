import { ArrowRight, Clock3, ScanLine } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader } from "../components/Primitives.jsx";

function completedAtLabel(value) {
  if (!value) return "Completion time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Completion time unavailable"
    : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export default function ScanHistory() {
  const navigate = useNavigate();
  const { scan, scans, selectedScanId, selectScan, storageError } = useScan();
  return <div className="page-content">
    <PageHeader eyebrow="WORKSPACE / ACTIVITY" title="Scan history" description="Completed live scans saved in this browser." action={<Link to="/scan" className="button button-primary"><ScanLine size={15} /> New scan</Link>} />
    {scan.isDemo && <DemoNotice />}
    {storageError && <div className="form-message form-error" role="status">{storageError}</div>}
    <section className="panel history-panel">
      <div className="panel-heading">
        <div><h2>Completed analyses</h2><p>Choose a scan to make it active across the dashboard, explorer, and reports.</p></div>
        <span className="panel-kicker">{scans.length} LIVE {scans.length === 1 ? "SCAN" : "SCANS"}</span>
      </div>
      {scans.length ? scans.map((item) => (
        <button
          type="button"
          className={`history-row ${item.id === selectedScanId ? "history-row-selected" : ""}`}
          key={item.id}
          aria-pressed={item.id === selectedScanId}
          onClick={() => {
            selectScan(item.id);
            navigate("/dashboard");
          }}
        >
          <span className="history-icon"><ScanLine size={18} /></span>
          <span className="history-project">
            <strong>{item.projectName}</strong>
            <span>{item.id} · {item.findings.length} findings · {item.endpoints.length} routes</span>
          </span>
          <span className="history-status"><i />{item.status}</span>
          <span className="history-time"><Clock3 size={14} />{completedAtLabel(item.completedAt)}</span>
          <span className="table-action" aria-hidden="true"><ArrowRight size={16} /></span>
        </button>
      )) : (
        <div className="history-placeholder">
          <Clock3 size={20} />
          <strong>No live scans saved yet</strong>
          <p>Upload a ZIP from New Scan to add real backend results to this history.</p>
        </div>
      )}
    </section>
  </div>;
}
