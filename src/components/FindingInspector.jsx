import { useEffect, useRef } from "react";
import { AlertTriangle, Check, CircleCheck, FileCode2, ShieldAlert, X } from "lucide-react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "./Primitives.jsx";
import CodeViewer from "./CodeViewer.jsx";

export default function FindingInspector({ finding, getReview, updateReview, removeFlag, onClose }) {
  const dialogRef = useRef(null);
  const review = getReview(finding.id);
  const line = finding.lineNumber ?? finding.line;
  const remediation = finding.remediation || finding.mitigation;
  const reason = finding.flagReason || finding.description;

  useEffect(() => {
    const previousFocus = document.activeElement;
    dialogRef.current?.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key === "Tab") {
        const focusable = [...dialogRef.current.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])')];
        if (!focusable.length) {
          event.preventDefault();
          dialogRef.current.focus();
        } else if (event.shiftKey && document.activeElement === focusable[0]) {
          event.preventDefault();
          focusable.at(-1).focus();
        } else if (!event.shiftKey && document.activeElement === focusable.at(-1)) {
          event.preventDefault();
          focusable[0].focus();
        }
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
    };
  }, [onClose]);

  return <div className="inspector-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section ref={dialogRef} className="finding-inspector" role="dialog" aria-modal="true" aria-labelledby="inspector-title" tabIndex="-1">
      <header className="inspector-header">
        <div><span className="eyebrow">FINDING CODE INSPECTION · {finding.id}</span><h2 id="inspector-title">{finding.title}</h2><div className="inspector-header-meta"><SeverityBadge severity={finding.severity} /><span className={`review-status review-status-${review.status.toLowerCase().replaceAll(" ", "-")}`}><span />{review.status}</span></div></div>
        <button type="button" className="icon-button inspector-close" aria-label="Close finding inspection" onClick={onClose}><X size={19} /></button>
      </header>
      <div className="inspector-body">
        <div className="inspector-source-meta"><span><FileCode2 size={14} />{finding.filePath || "File path not available"}{line ? `:${line}` : ""}</span><span>{finding.ruleId ? `Rule ${finding.ruleId}` : "Rule ID not available"}</span></div>
        <CodeViewer findings={[finding]} />
        <div className="inspector-detail-grid">
          <section className="inspector-info-card"><h3><ShieldAlert size={15} />Security explanation</h3><p>{finding.description || "Explanation not available from the backend."}</p>{finding.owaspCategory && <span className="context-tag">{finding.owaspCategory}</span>}</section>
          <section className="inspector-info-card"><h3><Check size={15} />Suggested remediation</h3><p>{remediation || "Remediation details not available from the backend."}</p></section>
        </div>
        {review.isFlagged && <section className="flag-reason-card"><div className="flag-reason-title"><AlertTriangle size={15} /><strong>Flagged for human review</strong></div><p>{reason || "Reason not available from the scanner."}</p><small>This is a review recommendation only. No source code was changed or removed.</small>{finding.saferAlternative ? <div className="safer-alternative"><strong>Suggested safer alternative</strong><p>{finding.saferAlternative}</p></div> : <div className="safer-alternative"><strong>Suggested safer alternative</strong><p>Not available for this finding.</p></div>}</section>}
        <section className="inspector-context">
          <div><span>Associated API endpoint</span>{finding.endpointId ? <Link to={`/endpoints/${finding.endpointId}`} onClick={onClose}>{finding.endpoint || "Open associated endpoint"}</Link> : <strong>{finding.endpoint || "Not available"}</strong>}</div>
          <div><span>OWASP category</span><strong>{finding.owaspCategory || "Not available"}</strong></div>
          <div><span>References</span><strong>{finding.references?.length ? finding.references.join(", ") : "Not available"}</strong></div>
        </section>
      </div>
      <footer className="inspector-actions">
        {review.isFlagged
          ? <button type="button" className="button button-outline" onClick={() => removeFlag(finding.id)}>Remove flag</button>
          : <button type="button" className="button button-flag" onClick={() => updateReview(finding.id, "Flagged for Removal", finding.description || "")}><AlertTriangle size={15} /> Flag for Removal</button>}
        <span className="inspector-action-note">{review.isFlagged ? "Flagged for human review only." : "Flagging never deletes or edits source code."}</span>
        <button type="button" className="button button-subtle" onClick={() => updateReview(finding.id, "Needs Review")}>Needs Review</button>
        <button type="button" className="button button-subtle" onClick={() => updateReview(finding.id, "Reviewed")}><Check size={14} /> Mark Reviewed</button>
        <button type="button" className="button button-primary" onClick={() => updateReview(finding.id, "Resolved")}><CircleCheck size={14} /> Mark Resolved</button>
      </footer>
    </section>
  </div>;
}
