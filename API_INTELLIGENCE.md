# API intelligence

`api_intelligence` statically discovers common FastAPI route decorators in a
Python project, adds conservative authentication review signals, correlates
normalized scanner findings, and can compare discovered routes with OpenAPI.
It parses source with Python's AST; it never imports or executes target code.

## Use

```python
from api_intelligence import analyze_project

intelligence = analyze_project(
    project_root="/path/to/project",
    findings=scan_result["findings"],
    openapi_spec="/path/to/openapi.json",  # optional; a parsed dict also works
)
```

The function returns a separate object with `routes`, `unmatched_findings`,
`errors`, `limitations`, and `openapi_comparison`. It does not modify the
existing scan result or its `status`, `findings`, `errors`, `exit_code`,
`duration_ms`, or `files_scanned` fields.

Each route includes `method`, `path`, `handler`, project-relative `file`,
decorator `line`, a `handler_range`, `security_signals`, and `findings`.
Correlated findings are wrapped as
`{"finding": <original normalized finding>, "correlation": <method>}`.
`handler_range` means the finding line falls inside the handler's source range.
`handler_match` is used only when finding data explicitly names the handler.
`file_only` is used only when the source file has exactly one discovered route.
Findings without a defensible association remain in `unmatched_findings`.

OpenAPI comparison accepts a JSON file path or parsed document. It reports
`undocumented_routes`; `include_documented_only=True` additionally reports
specification operations not discovered by static analysis. Missing or invalid
documents produce an `available: false` result and do not prevent discovery.
An undocumented route is a documentation/review signal, not a vulnerability.

## Security signals and limitations

`authentication_dependency_detected_statically` means a dependency declaration
has a recognizable authentication-related name. It does not establish that the
dependency is effective or correctly implemented.
`authentication_dependency_behavior_unknown` means a dependency exists but its
purpose is unclear. `authentication_not_detected_statically` means no
recognizable dependency was visible in the handler, its route decorator, or
statically recognizable router/application dependency configuration. It does
not prove that the route is unauthenticated; middleware, external gateways,
dynamic router registration, and inherited configuration may apply.
`inherited_authentication_configuration_unknown` separately indicates that
the route uses a router whose inclusion context could not be established in
the scanned source.

Only literal route paths and statically listed methods are discovered.
Dynamically built routes, mounted applications, aliases, configuration-driven
routers, and framework extensions may be missed. Syntax/read errors and routes
whose paths or methods cannot be resolved are returned separately. Findings
are matched by handler source range first; a file match alone is not used to
associate a finding with every endpoint. A file-only association is used only
when a finding has no usable line number and the file has exactly one route;
findings on a known line outside the handler range are left unmatched.

Run the tests with:

```powershell
python -m unittest discover -s tests -v
```

## HTTP scan endpoint

The standard-library WSGI application exposes `POST /api/v1/scan`. Run it for
local development with:

```powershell
python -m api_intelligence.http_api
```

The development server listens on `127.0.0.1:8000`. Send a
`multipart/form-data` request with a required `source_zip` file field and an
optional `openapi_json` file field:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/scan `
  -F "source_zip=@project.zip;type=application/zip" `
  -F "openapi_json=@openapi.json;type=application/json"
```

`source_zip` must have a `.zip` filename; `openapi_json`, when provided, must
have a `.json` filename and contain UTF-8 JSON with a `paths` object. The
request is limited to 20 MiB, OpenAPI input to 2 MiB, extraction to 100 MiB,
and 5,000 ZIP entries. ZIP paths must be relative and may not contain parent
traversal; symbolic links and special files are rejected. Uploaded code is
never executed, and the temporary extraction directory is removed after
analysis.

A successful response has this shape:

```json
{
  "status": "completed",
  "summary": {
    "routes_discovered": 1,
    "security_findings_available": true,
    "security_findings": 0
  },
  "findings": [],
  "routes": [
    {
      "method": "GET",
      "path": "/items",
      "handler": "items",
      "file": "app.py",
      "line": 3,
      "handler_range": {
        "start_line": 3,
        "end_line": 4
      },
      "security_signals": [
        "authentication_not_detected_statically"
      ],
      "findings": []
    }
  ],
  "unmatched_findings": [],
  "openapi_comparison": null,
  "errors": [],
  "limitations": []
}
```

The route entries use the internal API Intelligence field names documented
above. `openapi_comparison` is `null` when no specification was uploaded;
otherwise it contains the comparison result. `errors` and `limitations` come
from static route analysis. The endpoint runs the optional Bandit scanner when its executable is installed.
`security_findings_available` is `true` when the scanner completed successfully;
scanner errors are included in the response `errors` collection. Findings are
returned in `findings` and defensibly associated with routes when source file
and handler evidence supports the match. Authentication signals are
heuristics and do not establish whether an endpoint is actually protected.

For the browser workspace, the same backend also exposes `POST /api/scan` with
the frontend's `file` multipart field, and `GET /api/scans/{id}/findings` and
`GET /api/scans/{id}/routes`. These are an in-memory development compatibility
layer around the synchronous scan; production deployment should replace the
store with durable scan persistence.

Request errors use `{"error": {"kind": "...", "message": "..."}}`. The endpoint
returns `400` for malformed requests, `411` when `Content-Length` is missing
or invalid, `413` for size limits, `415` for unsupported content or filename
types, `422` for invalid ZIP/OpenAPI input or unsafe archive paths, `404` for
unknown paths, `405` for unsupported methods, and `500` for unexpected scan
failures. This WSGI application is a minimal integration point; production
deployment still requires a production WSGI server, network controls,
authentication/authorization, and operational timeouts.
