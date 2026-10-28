import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { MethodBadge, SeverityBadge } from "./Primitives.jsx";

export default function EndpointTable({ items }) {
  return (
    <div className="table-scroll">
      <table className="data-table endpoint-table">
        <thead><tr><th>Method</th><th>Endpoint</th><th>Documentation</th><th>Related findings</th><th>Severity</th><th /></tr></thead>
        <tbody>{items.map((endpoint) => {
          const mostSevere = endpoint.relatedFindings?.find((f) => f.severity === "High")
            || endpoint.relatedFindings?.find((f) => f.severity === "Medium")
            || endpoint.relatedFindings?.[0];
          return <tr key={endpoint.id}>
            <td><MethodBadge method={endpoint.method} /></td>
            <td><Link className="endpoint-link mono" to={`/endpoints/${endpoint.id}`}>{endpoint.path}</Link><div className="muted small">{endpoint.filePath}</div></td>
            <td><span className={`doc-status ${endpoint.documented ? "doc-ok" : "doc-missing"}`}><span />{endpoint.documented ? "Documented" : "Mismatch · undocumented"}</span></td>
            <td>{endpoint.relatedFindings?.length || 0}</td>
            <td>{mostSevere ? <SeverityBadge severity={mostSevere.severity} /> : <span className="muted">None</span>}</td>
            <td><Link className="table-action" to={`/endpoints/${endpoint.id}`} aria-label={`View ${endpoint.method} ${endpoint.path}`}><ArrowUpRight size={16} /></Link></td>
          </tr>;
        })}</tbody>
      </table>
    </div>
  );
}
