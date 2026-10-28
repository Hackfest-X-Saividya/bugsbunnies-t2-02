import { AlertTriangle, ArrowUpRight, Eye } from "lucide-react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "./Primitives.jsx";

export default function FindingsTable({ items, compact = false, onSelect, getReview }) {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Finding</th><th>Severity</th><th>Location</th>{!compact && <th>Endpoint</th>}<th>Review status</th><th>Inspect</th></tr></thead>
        <tbody>
          {items.map((finding) => (
            <tr key={finding.id} className={getReview?.(finding.id)?.isFlagged ? "finding-row-flagged" : ""}>
              <td><div className="finding-name">{getReview?.(finding.id)?.isFlagged && <AlertTriangle className="finding-flag-icon" size={14} aria-label="Flagged for review" />}{finding.title}</div><div className="muted small">{finding.id}</div></td>
              <td><SeverityBadge severity={finding.severity} /></td>
              <td><span className="mono">{finding.filePath || "Not available"}:{finding.line ?? "—"}</span></td>
              {!compact && <td><span className="mono">{finding.endpoint || "—"}</span></td>}
              <td><span className={`review-status review-status-${(getReview?.(finding.id)?.status || "Needs Review").toLowerCase().replaceAll(" ", "-")}`}><span />{getReview?.(finding.id)?.status || "Needs Review"}</span></td>
              <td><div className="finding-actions">{onSelect && <button className="table-action" type="button" aria-label={`Inspect code for ${finding.title}`} onClick={() => onSelect(finding)}><Eye size={16} /></button>}{finding.endpointId && <Link className="table-action" to={`/endpoints/${finding.endpointId}`} aria-label={`View endpoint for ${finding.title}`}><ArrowUpRight size={16} /></Link>}</div></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
