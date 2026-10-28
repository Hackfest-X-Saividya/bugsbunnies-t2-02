import { useMemo, useState } from "react";
import { ArrowLeft, ArrowUpRight, Bot, Check, Clipboard, FileCode2, ShieldAlert, Sparkles } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, FindingRating, MethodBadge, PageHeader } from "../components/Primitives.jsx";
import CodeViewer from "../components/CodeViewer.jsx";
import { explainFinding } from "../services/api.js";

export default function EndpointDetails() {
  const { id } = useParams();
  const { scan } = useScan();
  const [copied, setCopied] = useState("");
  const [explanation, setExplanation] = useState("");
  const [explainError, setExplainError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const endpoint = scan.endpoints.find((item) => item.id === id);
  const related = useMemo(() => endpoint ? scan.findings.filter((finding) => endpoint.findings?.includes(finding.id)) : [], [endpoint, scan.findings]);
  if (!endpoint) return <div className="page-content"><Link className="back-link" to="/explorer"><ArrowLeft size={15} /> Back to API Explorer</Link><div className="panel not-found"><ShieldAlert size={25} /><h2>Endpoint not found</h2><p>This route is not included in the currently selected scan.</p><Link className="button button-outline" to="/explorer">Browse API Explorer</Link></div></div>;

  const remediation = related[0]?.mitigation || "No scanner finding is associated with this route. Review authentication, authorization, input validation, and error handling as part of your normal security review.";
  const copyFix = async (finding) => {
    try {
      await navigator.clipboard.writeText(finding?.mitigation || finding?.remediation || remediation);
      setCopied(finding?.id || finding?.rule_id || "all");
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
          {related.length ? related.map((finding) => <article className="detail-finding" key={finding.id}><div className="detail-finding-head"><div><FindingRating finding={finding} /><span className="muted small mono">{finding.id || finding.rule_id}</span></div><span className="potential-label">Potential · verify manually</span></div><h3>{finding.title || finding.rule_id}</h3><div className="finding-source"><span>{finding.filePath ?? finding.file_path}:{finding.line}</span><span>Detection: {finding.source || finding.rule_id}</span>{finding.confidence && <span>{finding.confidence}</span>}</div><div className="finding-impact"><strong>Security impact</strong><p>{finding.impact || finding.description}</p></div>{(finding.evidence || finding.code) && <div className="finding-evidence"><strong>Evidence</strong><pre>{finding.evidence || finding.code}</pre></div>}<div className="recommendation"><div><strong>Suggested remediation</strong><p>{finding.mitigation || finding.remediation || "Review and remediate this finding based on the verified source context."}</p></div><button className="text-button" onClick={() => copyFix(finding)}><Clipboard size={14} />{copied === finding.id ? "Copied" : "Copy fix"}</button></div></article>) : <div className="no-findings"><span><Check size={17} /></span><div><strong>No scanner findings linked</strong><p>This route has no associated findings in this scan. This does not guarantee that the endpoint is risk-free.</p></div></div>}
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
