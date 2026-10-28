from zeroshadow_security.normalize import normalize_bandit_results


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


def test_rejects_malformed_results():
    try:
        normalize_bandit_results({"results": {}})
    except ValueError as exc:
        assert "array" in str(exc)
    else:
        raise AssertionError("malformed results should fail")
