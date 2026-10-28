import { Copy, FileCode2 } from "lucide-react";
import { useState } from "react";

export default function CodeViewer({ endpoint, findings = [] }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const snippets = findings.length
    ? findings.map((finding) => ({
        key: finding.id,
        filePath: finding.filePath,
        line: finding.lineNumber ?? finding.line,
        code: finding.evidence || finding.code || "",
      }))
    : endpoint
      ? [{ key: endpoint.id, filePath: endpoint.filePath, line: endpoint.line, code: Array.isArray(endpoint.code) ? endpoint.code.join("\n") : "" }]
      : [];
  const availableSnippets = snippets.filter((snippet) => snippet.code);
  const copyCode = async () => {
    setCopyError("");
    try {
      await navigator.clipboard.writeText(availableSnippets.map((snippet) => snippet.code).join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch (error) {
      setCopyError(`Could not copy source excerpt: ${error.message}`);
    }
  };
  const sourceTitle = endpoint?.path || findings[0]?.title || "selected finding";
  return (
    <section className="code-panel">
      <div className="code-panel-head"><div className="panel-title"><FileCode2 size={16} />Source preview <span className="code-file">{findings.length ? `${findings.length} finding excerpt${findings.length > 1 ? "s" : ""}` : endpoint?.filePath || "Source location"}</span></div><button disabled={!availableSnippets.length} className="text-button" onClick={copyCode}><Copy size={14} />{copied ? "Copied" : "Copy"}</button></div>
      {availableSnippets.length ? <div className="code-block" role="region" aria-label={`Source preview for ${sourceTitle}`} tabIndex={0}>
        {availableSnippets.map((snippet) => <div className="code-snippet" key={snippet.key}>
          {findings.length > 0 && <div className="snippet-file">{snippet.filePath || "File path not available"}<span>{snippet.line ? `line ${snippet.line}` : "Line number not available"}</span></div>}
          {snippet.code.split("\n").map((line, index) => {
            const lineNo = snippet.line ? snippet.line + index : null;
            return <div key={`${snippet.key}-${lineNo ?? index}`} className={`code-line ${findings.length > 0 ? "code-highlight" : ""}`}>
              <span className="line-number">{lineNo ?? "—"}</span><code>{line || " "}</code>{findings.length > 0 && index === 0 && <span className="line-marker">finding</span>}
            </div>;
          })}
        </div>)}
      </div> : <div className="code-unavailable" role="status"><FileCode2 size={18} /><span>Source excerpt not available from this scan.</span><small>The backend did not provide code evidence for this finding.</small></div>}
      {copyError && <div className="inline-error" role="alert">{copyError}</div>}
      <div className="code-caption"><span className="code-legend" />{findings.length ? "Scanner-provided excerpts are untrusted text; verify against the complete source." : "Route source preview · line numbers are relative to this excerpt."}</div>
    </section>
  );
}
