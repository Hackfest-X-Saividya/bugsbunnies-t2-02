# ZeroShadow AI — Security Intelligence Engine

ZeroShadow AI is a security-intelligence foundation for identifying actionable
Python security issues without executing the application being inspected.

## Status

This repository currently contains the first, contract-neutral security engine:

- safe Bandit subprocess execution with JSON parsing;
- explicit success versus scanner-execution failure states;
- exclusion of common virtual-environment, cache, build, and Git directories;
- file-count, file-size, and execution-time limits;
- normalized internal findings with source locations, rule identifiers, severity,
  evidence, curated OWASP mappings, and conservative remediation text;
- deterministic internal risk prioritization (not an ML prediction).

No public backend or authoritative **Vulnerability / Scanning API Response**
schema is present in the repository or supplied project files. The engine
therefore deliberately does **not** invent or serialize a competing public
response contract. The `ScanResult.to_internal_dict()` method is explicitly
internal and must not be used as an API response until the team supplies the
authoritative schema.

## How it works

```text
Python project
      |
      v
eligible-file checks ---> Bandit (JSON, no shell, no application execution)
      |
      v
normalized internal ScanResult ---> API adapter (to be implemented against the agreed schema)
```

Static analysis identifies source-level patterns. API intelligence can consume
the callable service and associate a finding with an endpoint only when it has
independent endpoint evidence; this package does not fabricate that association.

## Installation

Python 3.10 or newer is required.

```powershell
python -m pip install -e ".[scanner,test]"
```

Bandit is optional at the library level and is installed by the `scanner`
extra. Tests mock subprocess execution where appropriate.

## Scan

```python
from zeroshadow_security import SecurityIntelligenceService

result = SecurityIntelligenceService().scan("path/to/project")
print(result.status)
print(result.to_internal_dict())
```

`succeeded` means Bandit executed and produced parseable output. A successful
scan can contain findings. Missing executables, invalid paths, timeouts,
malformed JSON, and other scanner execution errors are represented separately
as `failed` with typed internal errors.

## Test

```powershell
python -m pytest
```

## Integration contract for teammates

1. Invoke `SecurityIntelligenceService().scan(target)` with a trusted local
   directory path.
2. Check `result.succeeded` before treating findings as complete scan output.
3. Keep `result.errors` separate from `result.findings`.
4. Adapt fields to the authoritative API model once it is supplied; do not
   expose `to_internal_dict()` directly.
5. Frontend code should consume the existing shared API response, not this
   internal model. Endpoint correlation is currently undefined and requires
   agreement with the API-intelligence owner.

## Limitations and roadmap

Bandit can produce false positives and false negatives and cannot guarantee
zero-day detection. The engine does not modify source code, execute uploaded
applications, or claim exploitability. OWASP and remediation mappings are
curated and intentionally incomplete. Planned work is to add the agreed
response adapter, integrate with the existing backend once it exists, and add
contract tests. ML and endpoint correlation remain out of scope until the
contract and evidence requirements are defined.

## License

No license has been supplied in the repository.
