from zeroshadow_security import Finding, ScanResult, ScanStatus
from zeroshadow_security.mappings import assess_finding_risk, normalize_risk_level
from zeroshadow_security.risk import sort_findings_by_priority, summarize_risk_levels


def test_deterministic_risk_scores_and_thresholds():
    low = Finding("B105", "Possible hardcoded password", "LOW", "app.py", evidence="password = 'secret'")
    assessment = assess_finding_risk(low)
    assert 0 <= assessment["score"] <= 100
    assert assessment["level"] in {"medium", "high"}
    assert assessment["status"] == "assessed"
    assert normalize_risk_level(18) == "low"
    assert normalize_risk_level(41) == "medium"
    assert normalize_risk_level(72) == "high"
    assert normalize_risk_level(92) == "critical"


def test_missing_evidence_keeps_assessment_uncertain():
    finding = Finding("B999", "Unknown issue", "UNDEFINED", "app.py")
    assessment = assess_finding_risk(finding)
    assert assessment["status"] == "uncertain"
    assert assessment["confidence"] == "low"
    assert assessment["impact"] is None
    assert assessment["exploitability"] is None
    assert assessment["exposure"] is None


def test_all_supported_severities_have_deterministic_levels():
    expected = {
        "CRITICAL": "high",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "low",
        "UNDEFINED": "low",
    }
    for severity, expected_level in expected.items():
        finding = Finding("B999", "Generic issue", severity, "app.py", evidence="observed")
        first = assess_finding_risk(finding)
        second = assess_finding_risk(finding)
        assert first == second
        assert first["level"] == expected_level


def test_every_finding_receives_risk_metadata():
    result = ScanResult(ScanStatus.SUCCEEDED, findings=[
        Finding("B608", "SQL injection", "HIGH", "db.py", evidence="SELECT * FROM users"),
        Finding("B501", "TLS check", "MEDIUM", "tls.py", evidence="ssl.create_default_context()"),
    ])
    for finding in result.findings:
        assessment = assess_finding_risk(finding)
        finding.risk_score = assessment["score"]
        finding.risk_level = assessment["level"]
        finding.risk_confidence = assessment["confidence"]
        finding.risk_status = assessment["status"]
        finding.risk_impact = assessment["impact"]
        finding.risk_exploitability = assessment["exploitability"]
        finding.risk_exposure = assessment["exposure"]
        finding.risk_evidence = assessment["evidence"]
        finding.risk_explanation = assessment["explanation"]
    assert all(item.risk_score is not None for item in result.findings)
    assert all(item.risk_level is not None for item in result.findings)


def test_risk_sorting_filters_and_summary_counts():
    findings = [
        Finding("B105", "Password", "LOW", "app.py", line=1),
        Finding("B608", "SQL", "HIGH", "db.py", line=2),
        Finding("B605", "No map", "MEDIUM", "other.py", line=3),
    ]
    for finding in findings:
        assessment = assess_finding_risk(finding)
        finding.risk_score = assessment["score"]
        finding.risk_level = assessment["level"]
        finding.risk_confidence = assessment["confidence"]
        finding.risk_status = assessment["status"]
        finding.risk_impact = assessment["impact"]
        finding.risk_exploitability = assessment["exploitability"]
        finding.risk_exposure = assessment["exposure"]
        finding.risk_evidence = assessment["evidence"]
        finding.risk_explanation = assessment["explanation"]

    ordered = sort_findings_by_priority(findings)
    assert ordered[0].rule_id == "B608"
    low_matches = sort_findings_by_priority(findings, risk_level="low")
    assert low_matches and low_matches[0].rule_id in {"B105", "B605"}
    assert sort_findings_by_priority(findings, severity="HIGH")[0].rule_id == "B608"
    summary = summarize_risk_levels(findings)
    assert summary["high"] >= 1
    assert summary["medium"] >= 1
