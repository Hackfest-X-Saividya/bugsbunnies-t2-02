from zeroshadow_security.normalize import normalize_bandit_results


def test_preserves_bandit_high_medium_and_low_severities():
    findings = normalize_bandit_results(
        {
            "results": [
                {"test_id": "B001", "filename": "high.py", "issue_severity": "HIGH"},
                {"test_id": "B002", "filename": "medium.py", "issue_severity": "MEDIUM"},
                {"test_id": "B003", "filename": "low.py", "issue_severity": "LOW"},
            ]
        }
    )
    assert [finding.severity for finding in findings] == ["HIGH", "MEDIUM", "LOW"]


def test_confidence_does_not_change_bandit_severity():
    findings = normalize_bandit_results(
        {
            "results": [
                {
                    "test_id": "B105",
                    "filename": "app.py",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                }
            ]
        }
    )
    assert findings[0].severity == "LOW"


def test_normalizes_finding_without_fabricating_optional_values():
    findings = normalize_bandit_results(
        {
            "results": [
                {
                    "test_id": "B105",
                    "issue_text": "Possible hardcoded password",
                    "issue_severity": "LOW",
                    "filename": "app.py",
                    "line_number": 8,
                    "code": "password = 'secret'",
                }
            ]
        }
    )
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].line == 8
    assert findings[0].owasp_category == "A07:2021 Identification and Authentication Failures"
    assert findings[0].references == ()
    assert findings[0].remediation is not None


def test_normalizes_missing_optional_fields_and_unknown_mapping():
    findings = normalize_bandit_results(
        {
            "results": [
                {
                    "test_id": "B999",
                    "issue_text": "Unknown test",
                    "issue_severity": "MEDIUM",
                    "filename": "app.py",
                }
            ]
        }
    )
    assert findings[0].line is None
    assert findings[0].evidence is None
    assert findings[0].owasp_category is None
    assert findings[0].remediation is None
    assert findings[0].references == ()


def test_rejects_malformed_results():
    try:
        normalize_bandit_results({"results": {}})
    except ValueError as exc:
        assert "array" in str(exc)
    else:
        raise AssertionError("malformed results should fail")
