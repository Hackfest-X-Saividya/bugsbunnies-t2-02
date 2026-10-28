import { useMemo, useState } from "react";
import { AlertTriangle, Download, Eye, FileDown, X } from "lucide-react";
import { SeverityBadge } from "./Primitives.jsx";

const reviewStatuses = ["Needs Review", "Flagged for Removal", "Reviewed", "Resolved"];

function safeCsvCell(value) {
  const text = String(value ?? "");
  const spreadsheetSafe = /^[\t\r ]*[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${spreadsheetSafe.replaceAll('"', '""')}"`;
}

export default function FlaggedCodePanel({ findings, getReview, removeFlag, onSelect }) {
  const [severityFilter, setSeverityFilter] = useState("All severities");
  const [fileFilter, setFileFilter] = useState("All files");
  const [statusFilter, setStatusFilter] = useState("All review statuses");
  const [downloadError, setDownloadError] = useState("");
  const flagged = useMemo(() => findings.filter((finding) => getReview(finding.id).isFlagged), [findings, getReview]);
  const files = useMemo(() => [...new Set(flagged.map((finding) => finding.filePath).filter(Boolean))].sort(), [flagged]);
  const severities = useMemo(() => [...new Set(flagged.map((finding) => finding.severity).filter(Boolean))].sort(), [flagged]);
  const visibleFindings = flagged.filter((finding) => {
    const review = getReview(finding.id);
    return (severityFilter === "All severities" || finding.severity === severityFilter)
      && (fileFilter === "All files" || finding.filePath === fileFilter)
      && (statusFilter === "All review statuses" || review.status === statusFilter);
  });

  const downloadReport = (format) => {
    try {
      const report = visibleFindings.map((finding) => {
        const review = getReview(finding.id);
        return {
          findingId: finding.id,
          ruleId: finding.ruleId || "",
          title: finding.title,
          filePath: finding.filePath || "",
          lineNumber: finding.lineNumber ?? finding.line ?? "",
          severity: finding.severity,
          reasonForFlagging: review.flagReason || finding.description || "Not available",
          suggestedAction: finding.saferAlternative || finding.remediation || finding.mitigation || "Not available",
          reviewStatus: review.status,
        };
      });
      const body = format === "json"
        ? JSON.stringify(report, null, 2)
        : [
            Object.keys(report[0] || {
              findingId: "", ruleId: "", title: "", filePath: "", lineNumber: "", severity: "",
              reasonForFlagging: "", suggestedAction: "", reviewStatus: "",
            }).map(safeCsvCell).join(","),
            ...report.map((item) => Object.values(item).map(safeCsvCell).join(",")),
          ].join("\r\n");
      const url = URL.createObjectURL(new Blob([body], { type: format === "json" ? "application/json;charset=utf-8" : "text/csv;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `shadowguard-flagged-code.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloadError("");
    } catch (error) {
      setDownloadError(`Could not download review report: ${error.message}`);
    }
  };

  return <section className="panel flagged-panel">
    <div className="panel-heading flagged-panel-heading">
      <div><h2><AlertTriangle size={15} />Flagged Code</h2><p>Human review queue · flagging does not remove source code</p></div>
      <div className="flagged-panel-actions"><span className="count-chip">{flagged.length}</span><button type="button" className="button button-subtle" disabled={!visibleFindings.length} onClick={() => downloadReport("csv")}><Download size={14} /> CSV</button><button type="button" className="button button-subtle" disabled={!visibleFindings.length} onClick={() => downloadReport("json")}><FileDown size={14} /> JSON</button></div>
    </div>
    {downloadError && <div className="form-message form-error" role="alert">{downloadError}</div>}
    {flagged.length > 0 && <div className="flag-filters">
      <label><span>Severity</span><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option>All severities</option>{severities.map((severity) => <option key={severity}>{severity}</option>)}</select></label>
      <label><span>File</span><select value={fileFilter} onChange={(event) => setFileFilter(event.target.value)}><option>All files</option>{files.map((file) => <option key={file}>{file}</option>)}</select></label>
      <label><span>Review status</span><select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option>All review statuses</option>{reviewStatuses.map((status) => <option key={status}>{status}</option>)}</select></label>
    </div>}
    {visibleFindings.length ? <div className="table-scroll">
      <table className="data-table flagged-table">
        <thead><tr><th>Finding ID</th><th>File & line</th><th>Severity</th><th>Reason for flagging</th><th>Suggested action</th><th>Review status</th><th>Actions</th></tr></thead>
        <tbody>{visibleFindings.map((finding) => {
          const review = getReview(finding.id);
          return <tr key={finding.id}>
            <td><strong className="finding-id">{finding.id}</strong></td>
            <td className="mono">{finding.filePath || "Not available"}:{finding.lineNumber ?? finding.line ?? "—"}</td>
            <td><SeverityBadge severity={finding.severity} /></td>
            <td className="flag-reason-cell">{review.flagReason || finding.description || "Not available"}</td>
            <td className="flag-reason-cell">{finding.saferAlternative || finding.remediation || finding.mitigation || "Not available"}</td>
            <td><span className={`review-status review-status-${review.status.toLowerCase().replaceAll(" ", "-")}`}><span />{review.status}</span></td>
            <td><div className="finding-actions"><button type="button" className="table-action" aria-label={`Inspect ${finding.id}`} onClick={() => onSelect(finding)}><Eye size={15} /></button><button type="button" className="table-action remove-flag-action" aria-label={`Remove flag from ${finding.id}`} onClick={() => removeFlag(finding.id)}><X size={15} /></button></div></td>
          </tr>;
        })}</tbody>
      </table>
    </div> : flagged.length ? <div className="table-empty">No flagged findings match these filters.</div> : <div className="flagged-empty"><span><AlertTriangle size={18} /></span><strong>No code has been flagged</strong><p>Inspect a finding and choose “Flag for Removal” to add it here for human review.</p></div>}
    <div className="table-footer"><span>Showing {visibleFindings.length} of {flagged.length} flagged findings</span><span>Source code is never changed by review flags.</span></div>
  </section>;
}
