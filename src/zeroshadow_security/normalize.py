"""Normalization of Bandit JSON into internal models."""

from collections.abc import Mapping
from typing import Any

from .mappings import owasp_for_rule, remediation_for_rule
from .models import Finding


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
        confidence = raw.get("issue_confidence")
        findings.append(
            Finding(
                rule_id=rule_id,
                test_id=rule_id,
                description=str(raw.get("issue_text", "Bandit finding")),
                severity=str(severity).upper(),
                path=path,
                line=raw.get("line_number") if isinstance(raw.get("line_number"), int) else None,
                evidence=raw.get("code") if isinstance(raw.get("code"), str) else None,
                owasp_category=owasp_for_rule(rule_id),
                remediation=remediation_for_rule(rule_id),
                references=tuple(raw.get("more_info") for _ in [0] if isinstance(raw.get("more_info"), str)),
            )
        )
    return findings
