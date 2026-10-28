"""Internal, contract-neutral models used until the authoritative API schema exists."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
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


@dataclass
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
    cwe: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    risk_confidence: str | None = None
    risk_status: str | None = None
    risk_impact: str | None = None
    risk_exploitability: str | None = None
    risk_exposure: str | None = None
    risk_evidence: str | None = None
    risk_explanation: str | None = None

    def with_risk_assessment(
        self,
        *,
        score: int | None,
        level: str | None,
        confidence: str | None,
        status: str | None,
        impact: str | None,
        exploitability: str | None,
        exposure: str | None,
        evidence: str | None,
        explanation: str | None,
    ) -> "Finding":
        return replace(
            self,
            risk_score=score,
            risk_level=level,
            risk_confidence=confidence,
            risk_status=status,
            risk_impact=impact,
            risk_exploitability=exploitability,
            risk_exposure=exposure,
            risk_evidence=evidence,
            risk_explanation=explanation,
        )


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

    @property
    def risk_summary(self) -> dict[str, int]:
        summary = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for finding in self.findings:
            level = (finding.risk_level or "informational").lower()
            if level in summary:
                summary[level] += 1
        return summary

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
                }
                for finding in self.findings
            ],
            "errors": [
                {"message": error.message, "kind": error.kind, "details": error.details}
                for error in self.errors
            ],
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
        }
