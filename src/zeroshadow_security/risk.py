"""Deterministic risk assessment and risk-based prioritization helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .mappings import RISK_LEVELS, normalize_risk_level, assess_finding_risk


def _coerce_finding(finding: Any) -> dict[str, Any]:
    if isinstance(finding, Mapping):
        data = dict(finding)
    else:
        data = {
            "rule_id": getattr(finding, "rule_id", "UNKNOWN"),
            "severity": getattr(finding, "severity", "UNDEFINED"),
            "risk_level": getattr(finding, "risk_level", None),
            "risk_score": getattr(finding, "risk_score", None),
            "risk_confidence": getattr(finding, "risk_confidence", None),
            "description": getattr(finding, "description", ""),
            "path": getattr(finding, "path", ""),
            "file_path": getattr(finding, "file_path", None),
            "line": getattr(finding, "line", None),
            "route": getattr(finding, "route", None),
            "evidence": getattr(finding, "evidence", None),
        }
    return data


def assess_risk(finding: Any) -> dict[str, Any]:
    """Return a deterministic assessment for a finding or mapping."""
    data = _coerce_finding(finding)
    result = assess_finding_risk(type("_Finding", (), data)())
    result["severity"] = str(data.get("severity", "UNDEFINED")).upper()
    return result


def sort_findings_by_priority(
    findings: Iterable[Any],
    *,
    descending: bool = True,
    risk_level: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    file_path: str | None = None,
    route: str | None = None,
) -> list[Any]:
    """Return findings ordered by risk using deterministic ties and supported filters."""
    ordered: list[Any] = []
    for item in findings:
        data = _coerce_finding(item)
        data_risk = str((data.get("risk_level") or "informational")).lower()
        if risk_level and data_risk != str(risk_level).lower():
            continue
        severity_value = str(data.get("severity") or "UNDEFINED").upper()
        if severity and severity_value != str(severity).upper():
            continue
        rule = str(data.get("rule_id") or "").lower()
        if rule_id and rule != str(rule_id).lower():
            continue
        path = str(data.get("path") or data.get("file_path") or "")
        if file_path and path != str(file_path):
            continue
        route_value = str(data.get("route") or "")
        if route and route_value != str(route):
            continue
        ordered.append(item)

    def sort_key(value: Any) -> tuple[int, int, str, str, int]:
        data = _coerce_finding(value)
        risk_score = int(data.get("risk_score") or assess_risk(value)["score"])
        severity_weight = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "UNDEFINED": 0}.get(str(data.get("severity") or "UNDEFINED").upper(), 0)
        path_value = str(data.get("path") or data.get("file_path") or "")
        rule_value = str(data.get("rule_id") or "")
        line_value = int(data.get("line") or 0)
        return (risk_score, severity_weight, path_value, rule_value, line_value)

    ordered.sort(key=sort_key, reverse=descending)
    return ordered


def summarize_risk_levels(findings: Iterable[Any]) -> dict[str, int]:
    counts = {level: 0 for level in RISK_LEVELS}
    for item in findings:
        data = _coerce_finding(item)
        level = str(data.get("risk_level") or normalize_risk_level(int(data.get("risk_score") or 0))).lower()
        if level in counts:
            counts[level] += 1
    return counts
