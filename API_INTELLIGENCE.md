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
