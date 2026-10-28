"""Normalization of Bandit JSON into internal models."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .mappings import assess_finding_risk, cwe_for_rule, owasp_for_rule, remediation_for_rule
from .models import Finding

_SEMGREP_LANGUAGE_BY_SUFFIX = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
}


def normalize_bandit_results(payload: Mapping[str, Any]) -> list[Finding]:
    raw_results = payload.get("results", [])
    if not isinstance(raw_results, list):
        raise ValueError("Bandit JSON field 'results' must be an array")

    findings: list[Finding] = []
    for raw in raw_results:
        if not isinstance(raw, Mapping):
            continue
        rule_id = raw.get("test_id")
        path = raw.get("filename")
        if not isinstance(rule_id, str) or not isinstance(path, str):
            continue
        severity = raw.get("issue_severity", "UNDEFINED")
        description = str(raw.get("issue_text", "Bandit finding"))
        evidence = raw.get("code") if isinstance(raw.get("code"), str) else None
        finding = Finding(
            rule_id=rule_id,
            test_id=rule_id,
            description=description,
            severity=str(severity).upper(),
            path=path,
            line=raw.get("line_number") if isinstance(raw.get("line_number"), int) else None,
            evidence=evidence,
            owasp_category=owasp_for_rule(rule_id),
            remediation=remediation_for_rule(rule_id),
            references=tuple(raw.get("more_info") for _ in [0] if isinstance(raw.get("more_info"), str)),
            cwe=cwe_for_rule(rule_id),
            language="python",
            analyzer="bandit",
        )
        assessment = assess_finding_risk(finding)
        findings.append(
            finding.with_risk_assessment(
                score=assessment["score"],
                level=assessment["level"],
                confidence=assessment["confidence"],
                status=assessment["status"],
                impact=assessment["impact"],
                exploitability=assessment["exploitability"],
                exposure=assessment["exposure"],
                evidence=assessment["evidence"],
                explanation=assessment["explanation"],
            )
        )
    return findings


def normalize_semgrep_results(payload: Mapping[str, Any], *, language: str | None = None) -> list[Finding]:
    raw_results = payload.get("results", [])
    if not isinstance(raw_results, list):
        raise ValueError("Semgrep JSON field 'results' must be an array")
    findings: list[Finding] = []
    for raw in raw_results:
        if not isinstance(raw, Mapping):
            continue
        check_id = raw.get("check_id")
        path = raw.get("path")
        start = raw.get("start")
        extra = raw.get("extra")
        if not isinstance(check_id, str) or not isinstance(path, str) or not isinstance(start, Mapping):
            continue
        message = extra.get("message") if isinstance(extra, Mapping) else None
        severity = extra.get("severity") if isinstance(extra, Mapping) else "UNDEFINED"
        lines = extra.get("lines") if isinstance(extra, Mapping) else None
        finding = Finding(
            rule_id=check_id,
            test_id=check_id,
            description=str(message or "Semgrep finding"),
            severity=str(severity).upper(),
            path=path,
            line=start.get("line") if isinstance(start.get("line"), int) else None,
            evidence=lines if isinstance(lines, str) else None,
            language=language or _SEMGREP_LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower()),
            analyzer="semgrep",
        )
        assessment = assess_finding_risk(finding)
        findings.append(
            finding.with_risk_assessment(
                score=assessment["score"],
                level=assessment["level"],
                confidence=assessment["confidence"],
                status=assessment["status"],
                impact=assessment["impact"],
                exploitability=assessment["exploitability"],
                exposure=assessment["exposure"],
                evidence=assessment["evidence"],
                explanation=assessment["explanation"],
            )
        )
    return findings
