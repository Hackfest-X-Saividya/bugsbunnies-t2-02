import { useMemo, useState } from "react";
import { ArrowDownToLine, Printer, ShieldCheck } from "lucide-react";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader, SeverityBadge } from "../components/Primitives.jsx";

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

export default function Reports() {
  const { scan } = useScan();
  const [downloadError, setDownloadError] = useState("");
  const summary = useMemo(() => ["High", "Medium", "Low"].map((severity) => ({
    severity,
    count: scan.findings.filter((finding) => finding.severity === severity).length,
  })), [scan.findings]);
  const affected = new Set(scan.findings.map((item) => item.endpointId).filter(Boolean)).size;
  const downloadReport = () => {
    try {
      const rows = [
        ["ID", "Title", "Severity", "Status", "File", "Line", "Endpoint", "Description", "Mitigation", "Detection source"],
        ...scan.findings.map((item) => [item.id, item.title, item.severity, item.status, item.filePath, item.line, item.endpoint, item.description, item.mitigation, item.source]),
      ];
      const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `shadowguard-${scan.id}-report.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloadError("");
    } catch (error) {
      setDownloadError(`Report download failed: ${error.message}`);
    }
  };
  return <div className="page-content report-page">
    <PageHeader eyebrow="WORKSPACE / EXPORTS" title="Security report" description={`A review-ready summary of the ${scan.projectName} analysis.`} action={<div className="report-actions"><button className="button button-subtle" onClick={() => window.print()}><Printer size={15} /> Print report</button><button className="button button-primary" onClick={downloadReport}><ArrowDownToLine size={15} /> Download CSV</button></div>} />
    {scan.isDemo && <DemoNotice />}
    {downloadError && <div className="form-message form-error" role="alert">{downloadError}</div>}
    <div className="report-cover panel"><div><div className="report-mark"><ShieldCheck size={23} /></div><div className="eyebrow">{scan.isDemo ? "DEMONSTRATION REPORT" : "SCAN REPORT"} · {scan.id}</div><h2>{scan.projectName}</h2><p>Application security analysis summary</p></div><div className="report-date"><span>REPORT GENERATED</span><strong>{new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(new Date())}</strong><span>STATUS · {scan.status}</span></div></div>
    <div className="report-summary-grid">
      <div className="report-summary panel"><span>Total findings</span><strong>{scan.findings.length}</strong><small>Potential scanner findings</small></div>
      {summary.map((item) => <div className={`report-summary panel report-${item.severity.toLowerCase()}`} key={item.severity}><span>{item.severity} severity</span><strong>{item.count}</strong><small><SeverityBadge severity={item.severity} /></small></div>)}
      <div className="report-summary panel"><span>Affected endpoints</span><strong>{affected}</strong><small>Of {scan.endpoints.length} discovered routes</small></div>
    </div>
    <section className="panel report-findings"><div className="panel-heading"><div><h2>Detailed findings</h2><p>Findings, source locations, and suggested remediation</p></div><span className="panel-kicker">{scan.findings.length} ITEMS</span></div>
      <div className="table-scroll"><table className="data-table report-table"><thead><tr><th>Finding</th><th>Severity</th><th>Source location</th><th>Affected endpoint</th><th>Recommended mitigation</th></tr></thead><tbody>{scan.findings.length ? scan.findings.map((finding) => <tr key={finding.id}><td><div className="finding-name">{finding.title}</div><div className="muted small">{finding.id} · {finding.source}</div></td><td><SeverityBadge severity={finding.severity} /></td><td><span className="mono">{finding.filePath}:{finding.line}</span></td><td><span className="mono">{finding.endpoint || "Not mapped"}</span></td><td className="mitigation-cell">{finding.mitigation}</td></tr>) : <tr><td colSpan="5" className="report-empty">No scanner findings are included in this scan.</td></tr>}</tbody></table></div>
    </section>
    <div className="report-disclaimer"><ShieldCheck size={15} /><span>Scanner output identifies potential risks, not confirmed vulnerabilities. Validate findings with the complete source and deployment context.</span></div>
  </div>;
}
