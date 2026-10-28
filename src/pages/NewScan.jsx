import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertCircle, ArrowRight, Check, CheckCircle2, Circle, FileArchive, FolderUp, LoaderCircle, Shield, Sparkles } from "lucide-react";
import { useScan } from "../context/ScanContext.jsx";
import { DemoNotice, PageHeader } from "../components/Primitives.jsx";
import { isDemoMode, getScanFindings, getScanRoutes, normalizeFindings, submitScan } from "../services/api.js";
import { validateProjectFile } from "../services/projectFileValidation.js";
import { endpoints, findings } from "../data/mockData.js";

const scanSteps = [
  "Uploading project",
  "Analyzing source code",
  "Detecting potential vulnerabilities",
  "Discovering API endpoints",
  "Correlating vulnerabilities with endpoints",
  "Generating security report",
];
const pause = (duration) => new Promise((resolve) => window.setTimeout(resolve, duration));

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
  const demoRunId = useRef(0);
  const navigate = useNavigate();
  const { setScan } = useScan();
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(null);

  useEffect(() => () => {
    demoRunId.current += 1;
  }, []);

  const acceptFile = (candidate) => {
    demoRunId.current += 1;
    setLoading(false);
    setError("");
    setProgress(null);
    if (!candidate) return;
    const validationError = validateProjectFile(candidate);
    if (validationError) {
      setFile(null);
      setError(validationError);
      return;
    }
    setFile(candidate);
  };

  const removeSelectedFile = () => {
    demoRunId.current += 1;
    setLoading(false);
    setFile(null);
    setProgress(null);
    if (fileInput.current) fileInput.current.value = "";
  };

  const startScan = async () => {
    if (!file) return;
    if (isDemoMode) {
      await runDemoProgress("uploaded-file");
      return;
    }
    setLoading(true);
    setError("");
    setProgress({ mode: "live", state: "uploading", activeIndex: 0 });
    try {
      const created = await submitScan(file);
      const scanId = created?.id ?? created?.scan_id;
      if (!scanId) throw new Error("The backend did not return a scan id.");
      setProgress({ mode: "live", state: "waiting", activeIndex: -1 });
      const [rawFindings, realEndpoints] = await Promise.all([getScanFindings(scanId), getScanRoutes(scanId)]);
      if (!Array.isArray(rawFindings) || !Array.isArray(realEndpoints)) {
        throw new Error("The backend response must include findings and routes as arrays.");
      }
      setScan({
        id: scanId,
        projectName: file.name.replace(/\.zip$/i, ""),
        status: "Complete",
        findings: normalizeFindings(rawFindings),
        endpoints: realEndpoints,
        isDemo: false,
      });
      navigate("/dashboard");
    } catch (requestError) {
      setError(requestError.message || "The scan could not be completed.");
      setProgress({ mode: "live", state: "error", activeIndex: 0 });
    } finally {
      setLoading(false);
    }
  };

  const runDemoProgress = async (kind, sample) => {
    const runId = demoRunId.current + 1;
    demoRunId.current = runId;
    setError("");
    setLoading(true);
    setProgress({ mode: "demo", state: "running", activeIndex: 0, kind });
    for (let index = 0; index < scanSteps.length; index += 1) {
      await pause(420);
      if (demoRunId.current !== runId) return;
      setProgress({ mode: "demo", state: "running", activeIndex: index + 1, kind });
    }
    if (demoRunId.current !== runId) return;
    if (kind === "uploaded-file") {
      setProgress({
        mode: "demo",
        state: "complete",
        activeIndex: scanSteps.length,
        kind,
        message: "Simulation complete. This archive was not uploaded or analyzed. Choose a built-in sample to view clearly labeled demonstration results.",
      });
      setLoading(false);
      return;
    }
    setProgress({
      mode: "demo",
      state: "complete",
      activeIndex: scanSteps.length,
      kind,
      message: "Simulated demo flow complete. The dashboard will show predefined demonstration data, not results from an actual scan.",
    });
    await pause(700);
    if (demoRunId.current !== runId) return;
    setScan({
      id: `demo-${sample.id}-01`,
      projectName: sample.title.replace(" FastAPI application", "").toLowerCase().replaceAll(" ", "-"),
      status: "Simulated demo",
      findings: sample.findings,
      endpoints: sample.endpoints,
      isDemo: true,
    });
    setLoading(false);
    navigate("/dashboard");
  };

  const formatFileSize = (size) => size < 1024 * 1024
    ? `${(size / 1024).toFixed(1)} KB`
    : `${(size / (1024 * 1024)).toFixed(2)} MB`;

  return <div className="page-content">
    <PageHeader eyebrow="WORKSPACE / NEW ANALYSIS" title="Upload your project" description="Analyze a Python project and connect code-level signals to your API surface." />
    {isDemoMode && <DemoNotice>Demo mode · Progress is simulated. Sample results are predefined; uploaded files stay on this device and are never analyzed.</DemoNotice>}
    <div className="scan-layout">
      <section className="panel upload-panel">
        <div className="section-title-row"><div><h2>Project archive</h2><p>Choose a ZIP archive containing Python or FastAPI source code.</p></div><span className="step-count">STEP 01 <ArrowRight size={13} /> 02</span></div>
        <div className={`drop-zone ${dragging ? "drop-active" : ""} ${file ? "drop-has-file" : ""}`}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => { event.preventDefault(); setDragging(false); acceptFile(event.dataTransfer.files?.[0]); }}>
          <input ref={fileInput} className="sr-only" type="file" accept=".zip,application/zip" aria-label="Choose a ZIP project archive" onChange={(event) => acceptFile(event.target.files?.[0])} />
          {file ? <><div className="drop-icon selected-file"><FileArchive size={23} /></div><strong>{file.name}</strong><span>{formatFileSize(file.size)} · ZIP selected · within 50 MB limit</span><button type="button" className="text-button" onClick={removeSelectedFile}>Remove file</button></>
            : <><div className="drop-icon"><FolderUp size={23} /></div><strong>Drop your project archive here</strong><span>ZIP files only · Maximum size 50 MB</span><button type="button" className="button button-outline" onClick={() => fileInput.current?.click()}>Browse files</button></>}
        </div>
        {error && <div className="form-message form-error" role="alert"><AlertCircle size={16} />{error}</div>}
        {progress && <section className={`scan-progress scan-progress-${progress.state}`} aria-live="polite">
          <div className="scan-progress-heading"><div><strong>{progress.mode === "demo" ? "Simulated scan progress" : progress.state === "error" ? "Scan request failed" : "Backend scan progress"}</strong><span>{progress.mode === "demo" ? "DEMO SIMULATION · NO SOURCE ANALYSIS" : "Live request · Backend step details are not available"}</span></div>{progress.state === "running" || progress.state === "waiting" || progress.state === "uploading" ? <LoaderCircle size={17} className="spin" /> : progress.state === "complete" ? <CheckCircle2 size={18} /> : <AlertCircle size={18} />}</div>
          <div className="progress-list">{scanSteps.map((step, index) => {
            const done = progress.mode === "demo" && progress.activeIndex > index;
            const active = progress.mode === "demo" && progress.state === "running" && progress.activeIndex === index
              || progress.mode === "live" && progress.state !== "error" && progress.state !== "complete" && progress.activeIndex === index;
            return <div key={step} className={`progress-step ${done ? "step-done" : ""} ${active ? "step-active" : ""}`}>
              <span className="progress-step-icon">{done ? <Check size={13} /> : active ? <LoaderCircle size={13} className="spin" /> : <Circle size={12} />}</span>
              <span>{step}</span>
              {progress.mode === "live" && progress.state === "waiting" && <small>Waiting for backend result</small>}
            </div>;
          })}</div>
          {progress.message && <div className={`progress-outcome ${progress.kind === "uploaded-file" ? "progress-outcome-warning" : ""}`}>{progress.kind === "uploaded-file" ? <AlertCircle size={15} /> : <CheckCircle2 size={15} />}{progress.message}</div>}
          {progress.mode === "live" && progress.state !== "error" && <div className="progress-live-note">The current API does not expose step-by-step progress. This indicator reports only the frontend request state.</div>}
        </section>}
        <div className="upload-footer"><div className="safe-note"><Shield size={16} /><span><strong>{isDemoMode ? "Demo uploads stay local." : "Sent only to your configured backend."}</strong><br />No third-party processing from this frontend.</span></div><button type="button" disabled={!file || loading} onClick={startScan} className="button button-primary">{loading ? <LoaderCircle className="spin" size={16} /> : <Sparkles size={16} />}{loading ? "Working…" : "Start Security Scan"}<ArrowRight size={15} /></button></div>
        <div className="format-note"><AlertCircle size={13} />Individual <code>.py</code> uploads are unavailable until the backend contract explicitly confirms support.</div>
      </section>
      <aside className="scan-aside">
        <div className="panel scan-checklist"><div className="panel-heading"><div><h2>Scan workflow</h2><p>Six stages from archive to report</p></div></div>{scanSteps.map((step, index) => <div className="checklist-item" key={step}><span className={`checklist-number ${index === 0 ? "current" : ""}`}>{String(index + 1).padStart(2, "0")}</span><div><strong>{step}</strong><span>{index === 0 ? "Validated project archive" : "Progress depends on backend response"}</span></div></div>)}</div>
        <div className="privacy-card"><Shield size={17} /><div><strong>Source code safety</strong><p>Source is never executed in your browser. Demo mode never uploads or analyzes your archive. Live uploads go only to the configured backend.</p></div></div>
      </aside>
    </div>
    <section className="sample-section"><div className="sample-heading"><div><span className="eyebrow">GET STARTED WITHOUT AN ARCHIVE</span><h2>Explore a sample project</h2><p>Load consistent demonstration data to preview the complete analysis workflow.</p></div><span className="demo-pill"><span /> DEMO MODE</span></div>
      <div className="sample-grid">{samples.map((sample) => <button type="button" key={sample.id} disabled={loading} onClick={() => runDemoProgress("sample", sample)} className="sample-card"><div className={`sample-card-icon ${sample.tone}`}>{loading ? <LoaderCircle className="spin" size={19} /> : <FileArchive size={19} />}</div><div className="sample-copy"><strong>{sample.title}</strong><span>{sample.detail} · predefined demo results</span></div><ArrowRight size={17} /></button>)}</div>
    </section>
  </div>;
}
