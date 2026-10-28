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
    }
