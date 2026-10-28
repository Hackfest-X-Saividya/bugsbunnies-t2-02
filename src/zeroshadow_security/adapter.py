"""Adapter from internal security results to the frozen v1 finding shape."""

from __future__ import annotations

from typing import Any

from .models import Finding, ScanResult


def to_security_findings(result: ScanResult) -> list[dict[str, Any]]:
    """Convert internal findings into the v1 ``security_findings`` shape.

    Bandit does not provide a separate title, so the existing issue description
    is used for both ``title`` and ``description``. Severity is lowercased only
    at this public adapter boundary.
    """
    return [_finding_to_v1(finding) for finding in result.findings]


def to_security_errors(result: ScanResult) -> list[dict[str, Any]]:
    """Convert internal scanner errors to the v1 security error shape."""
    return [
        {
            "code": error.kind,
            "message": error.message,
            "stage": "security_scan",
            **({"details": error.details} if error.details is not None else {}),
        }
        for error in result.errors
    ]


def _finding_to_v1(finding: Finding) -> dict[str, Any]:
    description = finding.description
    assessment = {
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "risk_confidence": finding.risk_confidence,
        "risk_status": finding.risk_status,
        "risk_impact": finding.risk_impact,
        "risk_exploitability": finding.risk_exploitability,
        "risk_exposure": finding.risk_exposure,
        "risk_evidence": finding.risk_evidence,
        "risk_explanation": finding.risk_explanation,
        "cwe": finding.cwe,
    }
    return {
        "rule_id": finding.rule_id,
        "title": description,
        "description": description,
        "severity": finding.severity.lower(),
        "file_path": finding.path,
        "line": finding.line,
        "evidence": finding.evidence,
        "owasp_category": finding.owasp_category,
        "remediation": finding.remediation,
        "references": list(finding.references),
        **{key: value for key, value in assessment.items() if value is not None},
    }
