import { ArrowUpRight, CircleHelp, Info } from "lucide-react";

export function PageHeader({ eyebrow, title, description, action }) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action && <div className="page-heading-action">{action}</div>}
    </div>
  );
}

export function DemoNotice({ children = "Demo data · Results shown are illustrative and are not from a live scan." }) {
  return <div className="demo-notice"><Info size={15} /><span>{children}</span></div>;
}

export function SeverityBadge({ severity }) {
  const label = severity || "Not available";
  const normalized = label.toLowerCase();
  const key = ["high", "medium", "low"].includes(normalized) ? normalized : "unknown";
  return <span className={`severity-badge severity-${key}`}><span />{label}</span>;
}

export function MethodBadge({ method }) {
  return <span className={`method-badge method-${method?.toLowerCase()}`}>{method}</span>;
}

export function StatCard({ label, value, note, icon: Icon, tone = "violet" }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon tone-${tone}`}><Icon size={18} /></div>
      <div className="stat-label">{label}<CircleHelp size={13} aria-label={`About ${label}`} /></div>
      <div className="stat-value">{value}</div>
      <div className="stat-note">{note}<ArrowUpRight size={13} /></div>
    </article>
  );
}

export function EmptyState({ title, message }) {
  return <div className="empty-state"><div className="empty-icon"><Info size={20} /></div><strong>{title}</strong><p>{message}</p></div>;
}
