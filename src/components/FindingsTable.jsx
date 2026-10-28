import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "./Primitives.jsx";

export default function FindingsTable({ items, compact = false }) {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Finding</th><th>Severity</th><th>Location</th>{!compact && <th>Endpoint</th>}<th>Status</th><th /></tr></thead>
        <tbody>
          {items.map((finding) => (
            <tr key={finding.id}>
              <td><div className="finding-name">{finding.title}</div><div className="muted small">{finding.id}</div></td>
              <td><SeverityBadge severity={finding.severity} /></td>
              <td><span className="mono">{finding.filePath}:{finding.line}</span></td>
              {!compact && <td><span className="mono">{finding.endpoint || "—"}</span></td>}
              <td><span className="review-status"><span />{finding.status}</span></td>
              <td><Link className="table-action" to={finding.endpointId ? `/endpoints/${finding.endpointId}` : "/explorer"} aria-label={`Inspect ${finding.title}`}><ArrowUpRight size={16} /></Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
