"""Curated Bandit mappings used for internal enrichment only."""

OWASP_BY_RULE: dict[str, str] = {
    "B102": "A03:2021 Injection",
    "B105": "A07:2021 Identification and Authentication Failures",
    "B106": "A07:2021 Identification and Authentication Failures",
    "B107": "A07:2021 Identification and Authentication Failures",
    "B608": "A03:2021 Injection",
    "B603": "A03:2021 Injection",
    "B324": "A02:2021 Cryptographic Failures",
    "B501": "A02:2021 Cryptographic Failures",
    "B506": "A08:2021 Software and Data Integrity Failures",
    "B701": "A05:2021 Security Misconfiguration",
}

REMEDIATION_BY_RULE: dict[str, str] = {
    "B105": "Do not hard-code passwords; load secrets from a protected secret store or environment.",
    "B106": "Do not pass hard-coded passwords; use a protected secret store or environment.",
    "B107": "Do not use a hard-coded password as a default argument.",
    "B608": "Use parameterized queries and validate inputs instead of constructing SQL with string formatting.",
    "B324": "Use a modern approved cryptographic hash for security-sensitive operations.",
    "B501": "Use a current TLS configuration and verify certificates.",
}

CWE_BY_RULE: dict[str, str] = {
    "B102": "CWE-78",
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B107": "CWE-798",
    "B608": "CWE-89",
    "B603": "CWE-78",
    "B324": "CWE-327",
    "B501": "CWE-295",
    "B506": "CWE-327",
    "B701": "CWE-327",
}


def owasp_for_rule(rule_id: str) -> str | None:
    return OWASP_BY_RULE.get(rule_id)


def remediation_for_rule(rule_id: str) -> str | None:
    return REMEDIATION_BY_RULE.get(rule_id)


def cwe_for_rule(rule_id: str) -> str | None:
    return CWE_BY_RULE.get(rule_id)


def risk_priority(severity: str, confidence: str | None = None) -> int:
    """Return an explainable internal rank; this is not an ML prediction."""
    severity_points = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNDEFINED": 0}
    confidence_points = {"HIGH": 1, "MEDIUM": 0, "LOW": -1}
    return severity_points.get(severity.upper(), 0) * 10 + confidence_points.get((confidence or "").upper(), 0)


RISK_LEVELS = ("informational", "low", "medium", "high", "critical")
RISK_THRESHOLDS = {
    "informational": 0,
    "low": 10,
    "medium": 35,
    "high": 60,
    "critical": 85,
}

SEVERITY_WEIGHT = {
    "CRITICAL": 35,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "INFORMATIONAL": 5,
    "UNDEFINED": 0,
}

SEVERITY_LEVEL_BONUS = {
    "CRITICAL": 25,
    "HIGH": 18,
    "MEDIUM": 10,
    "LOW": 4,
    "INFORMATIONAL": 0,
    "UNDEFINED": 0,
}

CONFIDENCE_WEIGHT = {
    "HIGH": 12,
    "MEDIUM": 8,
    "LOW": 4,
    "UNCERTAIN": 0,
    "UNKNOWN": 0,
}

RULE_IMPACT_WEIGHT = {
    "B105": 18,
    "B106": 18,
    "B107": 18,
    "B608": 22,
    "B603": 20,
    "B324": 12,
    "B501": 13,
    "B506": 10,
    "B701": 9,
}


def normalize_risk_level(score: int) -> str:
    for level in ("critical", "high", "medium", "low", "informational"):
        if score >= RISK_THRESHOLDS[level]:
            return level
    return "informational"


def assess_finding_risk(finding: object) -> dict[str, object]:
    """Deterministic risk assessment based on scanner severity and finding-specific evidence."""
    if not hasattr(finding, "rule_id"):
        raise ValueError("Finding is required")

    severity = str(getattr(finding, "severity", "UNDEFINED")).upper()
    rule_id = str(getattr(finding, "rule_id", "UNKNOWN"))
    raw_evidence = getattr(finding, "evidence", None)
    evidence = raw_evidence if isinstance(raw_evidence, str) and raw_evidence.strip() else ""
    description = (getattr(finding, "description", "") or "").strip()
    confidence = str(getattr(finding, "risk_confidence", "HIGH") or "HIGH").upper()
    if not evidence:
        confidence = "LOW"
        status = "uncertain"
    else:
        status = "assessed"

    score = SEVERITY_WEIGHT.get(severity, 0)
    score += SEVERITY_LEVEL_BONUS.get(severity, 0)
    score += CONFIDENCE_WEIGHT.get(confidence, 0)
    score += RULE_IMPACT_WEIGHT.get(rule_id, 0)

    evidence_text = evidence.lower()
    description_text = description.lower()
    evidence_bonus = 0
    if "password" in description_text or "secret" in evidence_text:
        evidence_bonus += 8
    if "sql" in description_text or "execute" in description_text or "format(" in evidence_text:
        evidence_bonus += 10
    if "tls" in description_text or "ssl" in description_text or "certificate" in description_text:
        evidence_bonus += 8
    score += evidence_bonus

    score = max(0, min(100, score))
    level = normalize_risk_level(score)

    if not evidence:
        impact = exploitability = exposure = None
    elif rule_id in {"B105", "B106", "B107"}:
        impact = "Credential exposure can enable account takeover or unauthorized access."
        exploitability = "Requires access to source or config data, often via code review or leakage."
        exposure = "High if secrets are deployed or embedded in repositories, low otherwise."
    elif rule_id in {"B608", "B603"}:
        impact = "Command or SQL execution can lead to data exfiltration or arbitrary code execution."
        exploitability = "Higher when user-controlled input reaches the query or command path."
        exposure = "Exposure depends on source and runtime surfaces that handle untrusted input."
    elif rule_id in {"B324", "B501", "B506", "B701"}:
        impact = "Weak crypto or transport security can permit bypass, downgrade, or integrity issues."
        exploitability = "Depends on the protocol, certificate handling, and attacker positioning."
        exposure = "Exposure increases when the component is internet-facing or handles sensitive data."
    else:
        impact = exploitability = exposure = None

    explanation = (
        f"Severity {severity.lower()} and rule {rule_id} contribute {SEVERITY_WEIGHT.get(severity, 0)} points; "
        f"rule impact contributes {RULE_IMPACT_WEIGHT.get(rule_id, 0)} points; "
        f"confidence contributes {CONFIDENCE_WEIGHT.get(confidence, 0)} points; "
        f"supported evidence contributes {evidence_bonus} points. "
        f"Total score {score} maps to {level} risk."
    )
    return {
        "score": score,
        "level": level,
        "confidence": confidence.lower() if confidence else "unknown",
        "status": status,
        "impact": impact,
        "exploitability": exploitability,
        "exposure": exposure,
        "evidence": evidence[:500] if evidence else None,
        "explanation": explanation,
    }
