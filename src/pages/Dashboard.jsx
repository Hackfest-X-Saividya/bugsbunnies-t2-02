import { useCallback, useMemo, useState } from "react";
import { Activity, AlertTriangle, ArrowRight, Braces, CircleCheck, Download, Eye, ShieldAlert } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { Link } from "react-router-dom";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader, StatCard } from "../components/Primitives.jsx";
import FindingsTable from "../components/FindingsTable.jsx";
import FindingInspector from "../components/FindingInspector.jsx";
import FlaggedCodePanel from "../components/FlaggedCodePanel.jsx";

const colors = { High: "#ef4444", Medium: "#f59e0b", Low: "#3b82f6" };

export default function Dashboard() {
  const { scan, getReview, updateReview, removeFlag } = useScan();
  const [query, setQuery] = useState("");
  const [selectedFinding, setSelectedFinding] = useState(null);
  const counts = useMemo(() => ["High", "Medium", "Low"].map((severity) => ({
    name: severity, value: scan.findings.filter((f) => f.severity === severity).length, color: colors[severity],
  })), [scan.findings]);
  const documentationData = [
    { name: "Documented", routes: scan.endpoints.filter((e) => e.documented).length, fill: "#38bdf8" },
    { name: "Undocumented", routes: scan.endpoints.filter((e) => !e.documented).length, fill: "#8b5cf6" },
  ];
  const visibleFindings = scan.findings.filter((finding) =>
    `${finding.id} ${finding.title} ${finding.filePath} ${finding.endpoint || ""}`.toLowerCase().includes(query.toLowerCase()),
  );
  const endpointCount = scan.endpoints.length;
  const reviewCounts = scan.findings.reduce((counts, finding) => {
    const review = getReview(finding.id);
    if (review.status === "Needs Review" || review.status === "Flagged for Removal") counts.needsReview += 1;
    if (review.isFlagged) counts.flagged += 1;
    return counts;
  }, { needsReview: 0, flagged: 0 });
  const closeInspector = useCallback(() => setSelectedFinding(null), []);

  return <div className="page-content">
    <PageHeader eyebrow="OVERVIEW / SECURITY POSTURE" title="Security dashboard" description={`A connected view of findings and API routes for ${scan.projectName}.`} action={<Link to="/scan" className="button button-primary"><Braces size={16} /> New scan</Link>} />
    {scan.isDemo && <DemoNotice />}
    <div className="stats-grid">
      <StatCard label="Total vulnerabilities" value={scan.findings.length} note="Across all severities" icon={ShieldAlert} />
      <StatCard label="High severity" value={counts[0].value} note="Prioritize review" icon={AlertTriangle} tone="red" />
      <StatCard label="Medium severity" value={counts[1].value} note="Review recommended" icon={Activity} tone="amber" />
      <StatCard label="Low severity" value={counts[2].value} note="Hardening opportunities" icon={CircleCheck} tone="blue" />
      <StatCard label="API endpoints" value={endpointCount} note={`${documentationData[1].routes} documentation mismatch`} icon={Braces} tone="cyan" />
      <StatCard label="Findings needing review" value={reviewCounts.needsReview} note="Needs Review or flagged" icon={Eye} tone="amber" />
      <StatCard label="Flagged for removal" value={reviewCounts.flagged} note="Human review only" icon={AlertTriangle} tone="red" />
    </div>
    <div className="chart-grid">
      <section className="panel chart-panel">
        <div className="panel-heading"><div><h2>Finding distribution</h2><p>Potential findings by severity</p></div><span className="panel-kicker">{scan.isDemo ? "DEMO DATA" : "LIVE SCAN"}</span></div>
        <div className="chart-inner">
          <div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={counts} dataKey="value" nameKey="name" innerRadius={66} outerRadius={88} paddingAngle={4} stroke="none">{counts.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie><Tooltip contentStyle={{ background: "#111d32", border: "1px solid #263650", borderRadius: 10, color: "#f8fafc" }} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{scan.findings.length}</strong><span>findings</span></div></div>
          <div className="chart-legend">{counts.map((item) => <div key={item.name}><span style={{ background: item.color }} />{item.name}<strong>{item.value}</strong></div>)}</div>
        </div>
      </section>
      <section className="panel chart-panel">
        <div className="panel-heading"><div><h2>Endpoint documentation</h2><p>Discovered route coverage</p></div><Link to="/explorer" className="inline-link">View routes <ArrowRight size={14} /></Link></div>
        <div className="bar-chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={documentationData} margin={{ top: 14, right: 12, left: -18, bottom: 0 }}><CartesianGrid stroke="#243149" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: "#94a3b8", fontSize: 12 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 11 }} /><Tooltip cursor={{ fill: "#ffffff08" }} contentStyle={{ background: "#111d32", border: "1px solid #263650", borderRadius: 10, color: "#f8fafc" }} /><Bar dataKey="routes" radius={[7, 7, 0, 0]} barSize={54}>{documentationData.map((item) => <Cell key={item.name} fill={item.fill} />)}</Bar></BarChart></ResponsiveContainer></div>
      </section>
    </div>
    <section className="panel findings-panel">
      <div className="panel-heading panel-heading-table"><div><h2>Potential vulnerabilities</h2><p>Select a finding to inspect its evidence and remediation.</p></div><div className="table-actions"><label className="search-field compact-search"><span className="sr-only">Search findings</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings..." /></label><Link to="/reports" className="button button-subtle"><Download size={15} /> Report</Link></div></div>
      <FindingsTable items={visibleFindings} onSelect={setSelectedFinding} getReview={getReview} />
      {visibleFindings.length === 0 && <div className="table-empty">No findings match “{query}”.</div>}
      <div className="table-footer"><span>Showing {visibleFindings.length} of {scan.findings.length} findings</span><Link to="/reports">View report <ArrowRight size={14} /></Link></div>
    </section>
    <FlaggedCodePanel findings={scan.findings} getReview={getReview} removeFlag={removeFlag} onSelect={setSelectedFinding} />
    <div className="scan-meta"><span className={`status-dot ${scan.isDemo ? "demo-status-dot" : ""}`} />{scan.isDemo ? `Demo results loaded · simulated flow · ${scan.id}` : `Scan complete · ${scan.id}`}<span>{scan.isDemo ? "Predefined demonstration dataset" : "Backend results"}</span></div>
    {selectedFinding && <FindingInspector finding={selectedFinding} getReview={getReview} updateReview={updateReview} removeFlag={removeFlag} onClose={closeInspector} />}
  </div>;
}
