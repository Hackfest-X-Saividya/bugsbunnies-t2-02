# ShadowGuard AI

Frontend for the BugsBunnies team project at HackFest 2026. ShadowGuard AI connects Python source-code security signals with discovered API endpoints.

## Run locally

Install and start the backend and frontend in separate PowerShell terminals:

```powershell
python -m pip install -e ".[scanner,test]"
python -m api_intelligence.http_api
```

In a second terminal:

```powershell
npm install
npm run dev
```

The backend listens on `http://127.0.0.1:8000` and the Vite frontend listens
on `http://localhost:5173`.

The app starts in **demo mode** when `VITE_API_BASE_URL` is not set. The built-in insecure and secure FastAPI samples load clearly labeled demonstration data. Uploaded archives are not sent anywhere in demo mode.

To enable backend integration, copy `.env.example` to `.env`, set
`VITE_API_BASE_URL=http://127.0.0.1:8000`, and restart Vite. The local backend
is a standard-library WSGI service, not FastAPI. Live scan requests use the
centralized service in `src/services/api.js`; failed backend requests are
shown as errors rather than replaced with mock results.

Check backend readiness before opening the workspace:

```powershell
curl.exe http://127.0.0.1:8000/health
```

The response should contain `"status":"ok"`. If the browser reports a
connection error, the backend process is not running or Vite was started
before `.env` was created; restart both processes.

## Frontend features

- Responsive landing page and workspace navigation
- Security dashboard with vulnerability and endpoint documentation charts
- ZIP upload validation (50 MB maximum) and sample project demos
- Searchable API explorer and endpoint risk inspection with finding excerpts
- Scan history and workspace integration settings
- Printable report and downloadable CSV export

All included scan results and source excerpts are fictional demonstration data. The browser does not execute uploaded source code.

## Package-level upload workflow

The package now provides `UploadScanWorkflow` for a future HTTP adapter. It
accepts archive bytes or a local archive path, validates ZIP members and
resource limits, calls an injected `MalwareScanner`, and runs Bandit only when
the malware result is `clean`. Suspicious, malware-detected, unavailable, and
scanner-failure results are quarantined and create a pending review; they
cannot reach static analysis through the workflow API.

```python
from zeroshadow_security import UploadScanWorkflow

result = UploadScanWorkflow().submit_archive(
    archive_bytes,
    upload_id="upload-123",
    uploader_id="user-456",
)
if result.scan is not None:
    findings = result.scan.findings
elif result.review is not None:
    review_id = result.review.review_id
```

`UploadLimits` configures archive bytes, file count, decompressed bytes,
archive depth, and scanner timeout. Archive paths are checked for traversal
and symlinks before extraction. No uploaded file is executed. The default
ClamAV adapter reports an unavailable result when its executable is absent;
unavailable is never treated as clean.

`ManagerReviewService` requires an injected `AuthorizationPolicy`,
`ReviewRepository`, and `NotificationSink` for production integration. The
included in-memory implementations are explicitly for local development and
tests only. Production deployment must replace them with authenticated
identity/role resolution, durable database storage, restricted quarantine
storage and lifecycle cleanup, and a durable notification provider. Approval
sets `execution_allowed` to `False` and authorizes static analysis only.

## Limitations and roadmap

Bandit can produce false positives and false negatives and cannot guarantee
zero-day detection. The engine does not modify source code, execute uploaded
applications, or claim exploitability. OWASP and remediation mappings are
curated and intentionally incomplete. Endpoint associations are only added
when source-file and handler evidence supports them. Production deployment
still requires durable scan/review persistence, authenticated authorization,
restricted quarantine storage, and a durable notification provider.

## License

No license has been supplied in the repository.
