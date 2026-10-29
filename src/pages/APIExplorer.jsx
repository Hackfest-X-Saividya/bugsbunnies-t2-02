import { useMemo, useState } from "react";
import { Search, SlidersHorizontal, Waypoints } from "lucide-react";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader, ScanStatusNotice } from "../components/Primitives.jsx";
import EndpointTable from "../components/EndpointTable.jsx";

export default function APIExplorer() {
  const { scan } = useScan();
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("All methods");
  const [docs, setDocs] = useState("All statuses");
  const endpoints = useMemo(() => scan.endpoints.map((endpoint) => ({
    ...endpoint,
    relatedFindings: scan.findings.filter((finding) => endpoint.findings?.includes(finding.id)),
  })).filter((endpoint) => {
    const matchesQuery = `${endpoint.path} ${endpoint.filePath}`.toLowerCase().includes(query.toLowerCase());
    const matchesMethod = method === "All methods" || endpoint.method === method;
    const matchesDocs = docs === "All statuses"
      || (docs === "Documented" && endpoint.documented === true)
      || (docs === "Undocumented" && endpoint.documented === false)
      || (docs === "Not compared" && (endpoint.documented === null || endpoint.documented === undefined));
    return matchesQuery && matchesMethod && matchesDocs;
  }), [scan, query, method, docs]);
  const undocumented = scan.endpoints.filter((endpoint) => endpoint.documented === false).length;
  const securityScanErrors = (scan.backendErrors || [])
    .filter((error) => error?.stage === "security_scan" && typeof error.message === "string")
    .map((error) => error.message);
  return <div className="page-content">
    <PageHeader eyebrow="SURFACE / ROUTE INVENTORY" title="API explorer" description="Search discovered routes and investigate how scanner findings relate to each endpoint." action={<div className="route-count"><Waypoints size={16} />{scan.endpoints.length} routes discovered</div>} />
    {scan.isDemo && <DemoNotice />}
    {!scan.isDemo && scan.securityFindingsAvailable === false && <ScanStatusNotice>{securityScanErrors.length
      ? `Route discovery completed, but the security scan failed: ${securityScanErrors.join(" ")}`
      : "This backend provides API route discovery only; it does not return source-code vulnerability findings."}</ScanStatusNotice>}
    {undocumented > 0 && <div className="mismatch-callout"><div className="callout-icon"><SlidersHorizontal size={17} /></div><div><strong>{undocumented} documentation {undocumented === 1 ? "mismatch" : "mismatches"} detected</strong><span>Undocumented routes indicate a documentation gap, not a confirmed vulnerability.</span></div></div>}
    <section className="panel explorer-panel">
      <div className="explorer-toolbar"><label className="search-field"><Search size={16} /><span className="sr-only">Search API endpoints</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search endpoint or source file…" /></label><div className="filter-fields"><label><span className="sr-only">Filter by HTTP method</span><select value={method} onChange={(event) => setMethod(event.target.value)}><option>All methods</option>{["GET", "POST", "PUT", "DELETE"].map((item) => <option key={item}>{item}</option>)}</select></label><label><span className="sr-only">Filter by documentation status</span><select value={docs} onChange={(event) => setDocs(event.target.value)}><option>All statuses</option><option>Documented</option><option>Undocumented</option><option>Not compared</option></select></label></div></div>
      <EndpointTable items={endpoints} />
      {endpoints.length === 0 && <div className="table-empty">No routes match the current search and filters.</div>}
      <div className="table-footer"><span>Showing {endpoints.length} of {scan.endpoints.length} discovered routes</span><span>Source: {scan.isDemo ? "Demo analysis" : "Live scan"}</span></div>
    </section>
  </div>;
}
