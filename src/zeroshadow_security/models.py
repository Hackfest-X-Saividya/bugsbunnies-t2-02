"""Internal, contract-neutral models used until the authoritative API schema exists."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class ScannerError:
    message: str
    kind: str
    details: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int | None = None
    test_id: str | None = None
    evidence: str | None = None
    owasp_category: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()
    cvss_vector: str | None = None


@dataclass
class ScanResult:
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScannerError] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = None
    files_scanned: int = 0

    @property
    def succeeded(self) -> bool:
        return self.status is ScanStatus.SUCCEEDED

    def to_internal_dict(self) -> dict[str, Any]:
        """Return a stable internal representation, not the public API contract."""
        return {
            "status": self.status.value,
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "description": finding.description,
                    "severity": finding.severity,
                    "path": finding.path,
                    "line": finding.line,
                    "test_id": finding.test_id,
                    "evidence": finding.evidence,
                    "owasp_category": finding.owasp_category,
                    "remediation": finding.remediation,
                    "references": list(finding.references),
                    **(
                        {"cvss_vector": finding.cvss_vector}
                        if finding.cvss_vector is not None
                        else {}
                    ),
                }
                for finding in self.findings
            ],
            "errors": [
                {
                    "message": error.message,
                    "kind": error.kind,
                    "details": error.details,
                }
                for error in self.errors
            ],
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
        }
