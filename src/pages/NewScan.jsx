import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertCircle, ArrowRight, Check, FileArchive, FolderUp, LoaderCircle, Shield, Sparkles } from "lucide-react";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader } from "../components/Primitives.jsx";
import { isDemoMode, getScanFindings, getScanRoutes, submitScan } from "../services/api.js";
import { endpoints, findings } from "../data/mockData.js";

const MAX_FILE_SIZE = 20 * 1024 * 1024;
const ACCEPTED_SOURCE_EXTENSIONS = [".zip", ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".swift", ".kt", ".kts", ".scala", ".sh"];
const secureEndpoints = endpoints.filter((endpoint) => endpoint.documented).map((endpoint) => ({
  ...endpoint,
  findings: [],
  code: {
    "get-user": [
      "async def get_user(user_id: str):",
      '    query = "SELECT * FROM users WHERE id = :user_id"',
      '    return await database.fetch_one(query, {"user_id": user_id})',
    ],
    "auth-login": [
      "async def login(payload: LoginRequest):",
      "    user = await authenticate(payload)",
      "    return create_token(user, settings.jwt_secret)",
    ],
    "account-detail": [
      "async def account_detail(account_id: str, user=Depends(current_user)):",
      "    await authorize_account_access(user, account_id)",
      "    return await account_service.get(account_id)",
    ],
    "health-check": [
      "app = FastAPI(debug=False)",
      "app.add_middleware(",
      '    CORSMiddleware, allow_origins=["https://app.example.test"],',
      ")",
    ],
  }[endpoint.id],
}));

const samples = [
  { id: "insecure", title: "Insecure FastAPI application", detail: "5 demo findings · 5 endpoints", tone: "rose", findings, endpoints },
  { id: "secure", title: "Secure FastAPI application", detail: "No findings · 4 documented endpoints", tone: "green", findings: [], endpoints: secureEndpoints },
];

export default function NewScan() {
  const fileInput = useRef(null);
  const navigate = useNavigate();
  const { setScan } = useScan();
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");

  const acceptFile = (candidate) => {
    setError("");
    setStatus("");
    if (!candidate) return;
    const extension = candidate.name.slice(candidate.name.lastIndexOf(".")).toLowerCase();
    if (!ACCEPTED_SOURCE_EXTENSIONS.includes(extension)) {
      setFile(null);
      setError(`Choose a supported source file or ZIP archive (${ACCEPTED_SOURCE_EXTENSIONS.join(", ")}).`);
      return;
    }
    if (candidate.size > MAX_FILE_SIZE) {
      setFile(null);
      setError("This file exceeds the 20 MB limit. Choose a smaller source file or archive.");
      return;
    }
    setFile(candidate);
  };

  const startScan = async () => {
    if (!file) return;
    if (isDemoMode) {
      setError("Live scanning is unavailable because no backend is configured. Use a sample project to explore demo results.");
      return;
    }
    setLoading(true);
    setError("");
    setStatus("Uploading source securely to your configured backend…");
    try {
      const created = await submitScan(file);
      const scanId = created?.id ?? created?.scan_id;
      if (!scanId) throw new Error("The backend did not return a scan id.");
      setStatus("Collecting scan findings and discovered routes…");
      const [realFindings, realEndpoints] = await Promise.all([getScanFindings(scanId), getScanRoutes(scanId)]);
      if (!Array.isArray(realFindings) || !Array.isArray(realEndpoints)) {
        throw new Error("The backend response must include findings and routes as arrays.");
      }
      setScan({
        id: scanId,
        projectName: file.name.replace(/\.[^.]+$/i, ""),
        status: "Complete",
        findings: realFindings,
        endpoints: realEndpoints,
        isDemo: false,
      });
      navigate("/dashboard");
    } catch (requestError) {
      setError(requestError.message || "The scan could not be completed.");
      setStatus("");
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (sample) => {
    setScan({
      id: `demo-${sample.id}-01`,
      projectName: sample.title.replace(" FastAPI application", "").toLowerCase().replaceAll(" ", "-"),
      status: "Demo data",
      findings: sample.findings,
      endpoints: sample.endpoints,
      isDemo: true,
    });
    navigate("/dashboard");
  };

  return <div className="page-content">
    <PageHeader eyebrow="WORKSPACE / NEW ANALYSIS" title="Upload your source" description="Analyze supported source files and connect Python API signals to your API surface." />
    {isDemoMode && <DemoNotice>Demo mode · No backend is configured. Sample projects use illustrative results; uploaded files are not sent anywhere.</DemoNotice>}
    <div className="scan-layout">
      <section className="panel upload-panel">
        <div className="section-title-row"><div><h2>Source input</h2><p>Choose a supported source file or ZIP archive.</p></div><span className="step-count">STEP 01 <ArrowRight size={13} /> 02</span></div>
        <div className={`drop-zone ${dragging ? "drop-active" : ""} ${file ? "drop-has-file" : ""}`}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => { event.preventDefault(); setDragging(false); acceptFile(event.dataTransfer.files?.[0]); }}>
          <input ref={fileInput} className="sr-only" type="file" accept={ACCEPTED_SOURCE_EXTENSIONS.join(",")} aria-label="Choose a source file or ZIP archive" onChange={(event) => acceptFile(event.target.files?.[0])} />
          {file ? <><div className="drop-icon selected-file"><FileArchive size={23} /></div><strong>{file.name}</strong><span>{(file.size / (1024 * 1024)).toFixed(2)} MB · Ready to scan</span><button className="text-button" onClick={() => { setFile(null); fileInput.current.value = ""; }}>Remove file</button></>
            : <><div className="drop-icon"><FolderUp size={23} /></div><strong>Drop source file or archive here</strong><span>Supported source formats · Maximum size 20 MB</span><button className="button button-outline" onClick={() => fileInput.current?.click()}>Browse files</button></>}
        </div>
        {error && <div className="form-message form-error" role="alert"><AlertCircle size={16} />{error}</div>}
        {status && <div className="form-message form-progress" role="status"><LoaderCircle className="spin" size={16} />{status}</div>}
        <div className="upload-footer"><div className="safe-note"><Shield size={16} /><span><strong>Your code stays in your workflow.</strong><br />No third-party processing from this frontend.</span></div><button disabled={!file || loading} onClick={startScan} className="button button-primary">{loading ? <LoaderCircle className="spin" size={16} /> : <Sparkles size={16} />}{loading ? "Analyzing…" : "Start scan"}<ArrowRight size={15} /></button></div>
      </section>
      <aside className="scan-aside">
        <div className="panel scan-checklist"><div className="panel-heading"><div><h2>What happens next?</h2><p>Built for a connected security review</p></div></div>{[["Upload project", "Select a ZIP archive"], ["Discover endpoints", "Map routes and documentation"], ["Review findings", "Inspect risks with endpoint context"]].map(([title, text], index) => <div className="checklist-item" key={title}><span className={`checklist-number ${index === 0 ? "current" : ""}`}>{index === 0 ? "01" : <Check size={14} />}</span><div><strong>{title}</strong><span>{text}</span></div></div>)}</div>
        <div className="privacy-card"><Shield size={17} /><div><strong>Source code safety</strong><p>Uploaded source is never executed in your browser. Live scans require a configured backend.</p></div></div>
      </aside>
    </div>
    <section className="sample-section"><div className="sample-heading"><div><span className="eyebrow">GET STARTED WITHOUT AN ARCHIVE</span><h2>Explore a sample project</h2><p>Load consistent demonstration data to preview the complete analysis workflow.</p></div><span className="demo-pill"><span /> DEMO MODE</span></div>
      <div className="sample-grid">{samples.map((sample) => <button key={sample.id} onClick={() => loadSample(sample)} className="sample-card"><div className={`sample-card-icon ${sample.tone}`}><FileArchive size={19} /></div><div className="sample-copy"><strong>{sample.title}</strong><span>{sample.detail}</span></div><ArrowRight size={17} /></button>)}</div>
    </section>
  </div>;
}
