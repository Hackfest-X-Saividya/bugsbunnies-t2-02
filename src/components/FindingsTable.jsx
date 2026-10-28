import { AlertTriangle, ArrowUpRight, Eye } from "lucide-react";
import { Link } from "react-router-dom";
import { FindingRating } from "./Primitives.jsx";

export default function FindingsTable({ items, compact = false, onSelect, getReview }) {
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr><th>Finding</th><th>Severity</th><th>Location</th>{!compact && <th>Endpoint</th>}<th>Review status</th><th>Inspect</th></tr></thead>
        <tbody>
          {items.map((finding) => {
            const review = getReview?.(finding.id);
            return (
              <tr key={finding.id} className={review?.isFlagged ? "finding-row-flagged" : ""}>
                <td><div className="finding-name">{review?.isFlagged && <AlertTriangle className="finding-flag-icon" size={14} aria-label="Flagged for review" />}{finding.title || finding.rule_id}</div><div className="muted small">{finding.id || finding.rule_id}</div></td>
                <td><FindingRating finding={finding} /></td>
                <td><span className="mono">{finding.filePath ?? finding.file_path ?? "Not available"}:{finding.lineNumber ?? finding.line_number ?? finding.line ?? "—"}</span></td>
                {!compact && <td><span className="mono">{finding.endpoint || "—"}</span></td>}
                <td><span className={`review-status review-status-${(review?.status || "Needs Review").toLowerCase().replaceAll(" ", "-")}`}><span />{review?.status || "Needs Review"}</span></td>
                <td><div className="finding-actions">{onSelect && <button className="table-action" type="button" aria-label={`Inspect code for ${finding.title || finding.rule_id}`} onClick={() => onSelect(finding)}><Eye size={16} /></button>}{finding.endpointId && <Link className="table-action" to={`/endpoints/${finding.endpointId}`} aria-label={`View endpoint for ${finding.title || finding.rule_id}`}><ArrowUpRight size={16} /></Link>}</div></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
