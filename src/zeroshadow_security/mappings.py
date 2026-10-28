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


def owasp_for_rule(rule_id: str) -> str | None:
    return OWASP_BY_RULE.get(rule_id)


def remediation_for_rule(rule_id: str) -> str | None:
    return REMEDIATION_BY_RULE.get(rule_id)


def risk_priority(severity: str, confidence: str | None = None) -> int:
    """Return an explainable internal rank; this is not an ML prediction."""
    severity_points = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNDEFINED": 0}
    confidence_points = {"HIGH": 1, "MEDIUM": 0, "LOW": -1}
    return severity_points.get(severity.upper(), 0) * 10 + confidence_points.get((confidence or "").upper(), 0)
