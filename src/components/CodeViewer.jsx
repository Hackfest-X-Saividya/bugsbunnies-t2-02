import { Copy, FileCode2 } from "lucide-react";
import { useState } from "react";

export default function CodeViewer({ endpoint, findings = [] }) {
  const [copied, setCopied] = useState(false);
  const snippets = findings.length
    ? findings.map((finding) => ({
        key: finding.id,
        filePath: finding.filePath,
        line: finding.line,
        code: finding.code || finding.title,
      }))
    : [{ key: endpoint.id, filePath: endpoint.filePath, line: 1, code: (endpoint.code || []).join("\n") }];
  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(snippets.map((snippet) => snippet.code).join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch (error) {
      console.error("Could not copy source code:", error);
    }
  };
  return (
    <section className="code-panel">
      <div className="code-panel-head"><div className="panel-title"><FileCode2 size={16} />Source preview <span className="code-file">{findings.length ? `${findings.length} finding excerpt${findings.length > 1 ? "s" : ""}` : endpoint.filePath}</span></div><button className="text-button" onClick={copyCode}><Copy size={14} />{copied ? "Copied" : "Copy"}</button></div>
      <div className="code-block" role="region" aria-label={`Source preview for ${endpoint.path}`} tabIndex={0}>
        {snippets.map((snippet) => <div className="code-snippet" key={snippet.key}>
          {findings.length > 0 && <div className="snippet-file">{snippet.filePath}<span>line {snippet.line}</span></div>}
          {snippet.code.split("\n").map((line, index) => {
            const lineNo = snippet.line + index;
            return <div key={`${snippet.key}-${lineNo}`} className={`code-line ${findings.length > 0 ? "code-highlight" : ""}`}>
              <span className="line-number">{lineNo}</span><code>{line || " "}</code>{findings.length > 0 && index === 0 && <span className="line-marker">finding</span>}
            </div>;
          })}
        </div>)}
      </div>
      <div className="code-caption"><span className="code-legend" />{findings.length ? "Finding excerpts are untrusted scanner output; verify against the complete source." : "Route source preview · line numbers are relative to this excerpt."}</div>
    </section>
  );
}
