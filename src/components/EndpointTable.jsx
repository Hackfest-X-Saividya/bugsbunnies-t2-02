import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { FindingRating, MethodBadge } from "./Primitives.jsx";
import { resolveFindingRating, SEVERITY_ORDER } from "../services/findingRating.js";

export default function EndpointTable({ items }) {
  return (
    <div className="table-scroll">
      <table className="data-table endpoint-table">
        <thead><tr><th>Method</th><th>Endpoint</th><th>Documentation</th><th>Related findings</th><th>Severity</th><th /></tr></thead>
        <tbody>{items.map((endpoint) => {
          const mostSevere = endpoint.relatedFindings?.reduce((highest, finding) => {
            if (!highest) return finding;
            const currentRating = resolveFindingRating(finding).severity;
            const highestRating = resolveFindingRating(highest).severity;
            return SEVERITY_ORDER.indexOf(currentRating) < SEVERITY_ORDER.indexOf(highestRating)
              ? finding
              : highest;
          }, null);
          return <tr key={endpoint.id}>
            <td><MethodBadge method={endpoint.method} /></td>
            <td><Link className="endpoint-link mono" to={`/endpoints/${endpoint.id}`}>{endpoint.path}</Link><div className="muted small">{endpoint.filePath}</div></td>
            <td><span className={`doc-status ${endpoint.documented === true ? "doc-ok" : endpoint.documented === false ? "doc-missing" : ""}`}><span />{endpoint.documented === true ? "Documented" : endpoint.documented === false ? "Undocumented" : "Not compared"}</span></td>
            <td>{endpoint.relatedFindings?.length || 0}</td>
            <td>{mostSevere ? <FindingRating finding={mostSevere} compact /> : <span className="muted">None</span>}</td>
            <td><Link className="table-action" to={`/endpoints/${endpoint.id}`} aria-label={`View ${endpoint.method} ${endpoint.path}`}><ArrowUpRight size={16} /></Link></td>
          </tr>;
        })}</tbody>
      </table>
    </div>
  );
}
