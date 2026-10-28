import { useMemo, useState } from "react";
import { AlertTriangle, ArrowLeft, ArrowUpRight, Bot, Check, Clipboard, FileCode2, ShieldAlert, Sparkles } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, MethodBadge, PageHeader, SeverityBadge } from "../components/Primitives.jsx";
import CodeViewer from "../components/CodeViewer.jsx";
import { explainFinding } from "../services/api.js";

export default function EndpointDetails() {
  const { id } = useParams();
  const { scan, getReview, updateReview, removeFlag } = useScan();
  const [copied, setCopied] = useState("");
  const [explanation, setExplanation] = useState("");
  const [explainError, setExplainError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const endpoint = scan.endpoints.find((item) => item.id === id);
  const related = useMemo(() => endpoint ? scan.findings.filter((finding) => (
    endpoint.findings?.includes(finding.id)
    || finding.endpointId === endpoint.id
    || finding.endpoint === `${endpoint.method} ${endpoint.path}`
    || finding.endpoint === endpoint.path
  )) : [], [endpoint, scan.findings]);
  if (!endpoint) return <div className="page-content"><Link className="back-link" to="/explorer"><ArrowLeft size={15} /> Back to API Explorer</Link><div className="panel not-found"><ShieldAlert size={25} /><h2>Endpoint not found</h2><p>This route is not included in the currently selected scan.</p><Link className="button button-outline" to="/explorer">Browse API Explorer</Link></div></div>;

  const remediation = related[0]?.mitigation || "No scanner finding is associated with this route. Review authentication, authorization, input validation, and error handling as part of your normal security review.";
  const copyFix = async (finding) => {
    try {
      await navigator.clipboard.writeText(finding?.mitigation || remediation);
      setCopied(finding?.id || "all");
      window.setTimeout(() => setCopied(""), 1600);
    } catch (error) {
      setExplainError(`Could not copy to clipboard: ${error.message}`);
    }
  };
  const requestExplanation = async () => {
    setExplainError("");
    if (scan.isDemo) {
      setExplanation("This is an illustrative demo explanation. The route is connected to scanner signals shown below; verify each potential issue against the full project and deployment context before treating it as confirmed.");
      return;
    }
    setExplaining(true);
    try {
      const result = await explainFinding({ endpoint, findings: related });
      if (typeof result?.explanation !== "string") throw new Error("The backend response did not contain an explanation.");
      setExplanation(result.explanation);
    } catch (error) {
      setExplainError(error.message || "Could not retrieve an explanation.");
    } finally {
      setExplaining(false);
    }
  };

  return <div className="page-content">
    <Link className="back-link" to="/explorer"><ArrowLeft size={15} /> Back to API Explorer</Link>
    {scan.isDemo && <DemoNotice />}
    <div className="endpoint-title panel">
      <div className="endpoint-title-main"><div className="endpoint-symbol"><FileCode2 size={20} /></div><div><div className="eyebrow">ENDPOINT RISK X-RAY <span className="endpoint-id">· {endpoint.id}</span></div><div className="endpoint-heading"><MethodBadge method={endpoint.method} /><h1>{endpoint.path}</h1></div><p>{endpoint.summary}</p></div></div>
      <div className={`doc-status ${endpoint.documented ? "doc-ok" : "doc-missing"}`}><span />{endpoint.documented ? "Documented" : "Documentation mismatch"}</div>
    </div>
    {!endpoint.documented && <div className="mismatch-callout"><div className="callout-icon"><ShieldAlert size={17} /></div><div><strong>Undocumented route — documentation mismatch</strong><span>This is a documentation gap and is not, by itself, a confirmed vulnerability.</span></div></div>}
    <div className="endpoint-meta-grid">
      <div className="meta-card"><span>Source location</span><strong className="mono">{endpoint.filePath}:{endpoint.line}</strong></div>
      <div className="meta-card"><span>Related findings</span><strong>{related.length} <small>{related.length === 1 ? "potential signal" : "potential signals"}</small></strong></div>
      <div className="meta-card"><span>Review status</span><strong><span className="status-dot" />{related.length ? "Review recommended" : "No scanner findings"}</strong></div>
    </div>
    <div className="inspection-grid">
      <div className="inspection-main">
        <CodeViewer endpoint={endpoint} findings={related} />
        <section className="panel findings-detail-panel"><div className="panel-heading"><div><h2>Associated findings</h2><p>Signals mapped to this endpoint</p></div><span className="count-chip">{related.length}</span></div>
          {related.length ? related.map((finding) => {
            const review = getReview(finding.id);
            return <article className="detail-finding" key={finding.id}>
              <div className="detail-finding-head"><div><SeverityBadge severity={finding.severity} /><span className="muted small mono">{finding.id}</span></div><span className={`review-status review-status-${review.status.toLowerCase().replaceAll(" ", "-")}`}><span />{review.status}</span></div>
              <h3>{finding.title}</h3><p>{finding.description || "Explanation not available from the backend."}</p>
              <div className="finding-source"><span>{finding.filePath || "File path not available"}:{finding.lineNumber ?? finding.line ?? "—"}</span><span>Detection: {finding.source || "Not available"}</span><span>{finding.confidence || "Confidence not available"}</span></div>
              <div className="recommendation"><div><strong>Suggested remediation</strong><p>{finding.remediation || finding.mitigation || "Not available from the backend."}</p></div>{(finding.remediation || finding.mitigation) && <button className="text-button" onClick={() => copyFix(finding)}><Clipboard size={14} />{copied === finding.id ? "Copied" : "Copy fix"}</button>}</div>
              {review.isFlagged && <div className="endpoint-flag-note"><AlertTriangle size={14} /><span>Flagged for human review · {review.flagReason || finding.description || "Reason not available."} No source code was changed.</span></div>}
              <div className="endpoint-review-actions">
                {review.isFlagged
                  ? <button className="text-button" onClick={() => removeFlag(finding.id)}>Remove flag</button>
                  : <button className="text-button flag-action" onClick={() => updateReview(finding.id, "Flagged for Removal", finding.description || "")}><AlertTriangle size={13} />Flag for Removal</button>}
                <button className="text-button" onClick={() => updateReview(finding.id, "Reviewed")}>Mark Reviewed</button>
                <button className="text-button" onClick={() => updateReview(finding.id, "Resolved")}>Mark Resolved</button>
              </div>
            </article>;
          }) : <div className="no-findings"><span><Check size={17} /></span><div><strong>No scanner findings linked</strong><p>This route has no associated findings in this scan. This does not guarantee that the endpoint is risk-free.</p></div></div>}
        </section>
      </div>
      <aside className="inspection-aside">
        <section className="insight-card"><div className="insight-heading"><span><Sparkles size={16} /></span><div><strong>AI security explanation</strong><small>{scan.isDemo ? "ILLUSTRATIVE DEMO" : "BACKEND ASSISTED"}</small></div></div>{explanation ? <p>{explanation}</p> : <p>Get a plain-language explanation of the scanner signals associated with this endpoint.</p>}{explainError && <div className="inline-error">{explainError}</div>}<button disabled={explaining} className="button button-outline full-width" onClick={requestExplanation}>{explaining ? "Generating…" : <><Bot size={15} /> Explain findings <ArrowUpRight size={14} /></>}</button></section>
        <section className="panel endpoint-info"><div className="panel-heading"><div><h2>Route context</h2><p>Discovered endpoint details</p></div></div><div className="context-row"><span>HTTP method</span><MethodBadge method={endpoint.method} /></div><div className="context-row"><span>Source file</span><strong className="mono">{endpoint.filePath}</strong></div><div className="context-row"><span>Source line</span><strong>{endpoint.line}</strong></div><div className="context-row"><span>Parameters</span><div>{endpoint.parameters?.length ? endpoint.parameters.map((param) => <span className="param-chip" key={param}>{param}</span>) : <span className="muted">None detected</span>}</div></div></section>
        <div className="review-note"><ShieldAlert size={15} /><span>Scanner output identifies potential risks. Confirm each issue in the complete source and deployment context.</span></div>
      </aside>
    </div>
  </div>;
}
