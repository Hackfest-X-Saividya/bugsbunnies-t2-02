from zeroshadow_security import (
    Finding,
    ScanResult,
    ScanStatus,
    ScannerError,
    to_security_errors,
    to_security_findings,
)


def test_adapts_finding_to_v1_security_findings():
    finding = Finding(
        rule_id="B105",
        description="Possible hardcoded password",
        severity="LOW",
        path="app.py",
        line=8,
        evidence="password = 'secret'",
        owasp_category="A07:2021 Identification and Authentication Failures",
        remediation="Use a protected secret store.",
        references=("https://example.test/b105",),
    )
    result = ScanResult(ScanStatus.SUCCEEDED, findings=[finding])

    adapted = to_security_findings(result)

    assert len(adapted) == 1
    assert set(adapted[0]) == {
        "rule_id",
        "title",
        "description",
        "severity",
        "file_path",
        "line",
        "evidence",
        "owasp_category",
        "remediation",
        "references",
    }
    assert adapted[0]["severity"] == "low"
    assert adapted[0]["title"] == "Possible hardcoded password"
    assert adapted[0]["description"] == "Possible hardcoded password"
    assert adapted[0]["file_path"] == "app.py"
    assert adapted[0]["references"] == ["https://example.test/b105"]


def test_adapter_lowercases_supported_severities():
    result = ScanResult(
        ScanStatus.SUCCEEDED,
        findings=[
            Finding("B001", "High", "HIGH", "high.py"),
            Finding("B002", "Medium", "MEDIUM", "medium.py"),
            Finding("B003", "Low", "LOW", "low.py"),
        ],
    )

    assert [item["severity"] for item in to_security_findings(result)] == [
        "high",
        "medium",
        "low",
    ]


def test_unknown_values_remain_null_and_severity_is_lowercase():
    finding = Finding("B999", "Unknown test", "UNDEFINED", "app.py")
    result = ScanResult(ScanStatus.SUCCEEDED, findings=[finding])

    adapted = to_security_findings(result)[0]

    assert adapted["severity"] == "undefined"
    assert adapted["line"] is None
    assert adapted["evidence"] is None
    assert adapted["owasp_category"] is None
    assert adapted["remediation"] is None
    assert adapted["references"] == []


def test_adapts_scanner_errors_without_hiding_cause():
    result = ScanResult(
        ScanStatus.FAILED,
        errors=[ScannerError("Bandit executable was not found", "missing_executable")],
    )

    assert to_security_errors(result) == [
        {
            "code": "missing_executable",
            "message": "Bandit executable was not found",
            "stage": "security_scan",
        }
    ]


def test_adapts_error_details_when_available():
    result = ScanResult(
        ScanStatus.FAILED,
        errors=[ScannerError("Bandit failed", "scanner_error", "stderr output")],
    )

    assert to_security_errors(result)[0]["details"] == "stderr output"


def test_clean_scan_adapts_to_empty_findings():
    result = ScanResult(ScanStatus.SUCCEEDED)

    assert to_security_findings(result) == []
    assert to_security_errors(result) == []


def test_distinct_findings_are_not_deduplicated():
    result = ScanResult(
        ScanStatus.SUCCEEDED,
        findings=[
            Finding("B105", "Hard-coded password", "LOW", "first.py", line=1),
            Finding("B105", "Hard-coded password", "LOW", "second.py", line=1),
        ],
    )

    adapted = to_security_findings(result)

    assert len(adapted) == 2
    assert adapted[0]["file_path"] != adapted[1]["file_path"]


def test_calculates_cvss_from_vector_and_ignores_supplied_score():
    from zeroshadow_security.normalize import normalize_bandit_results

    findings = normalize_bandit_results(
        {
            "results": [
                {
                    "test_id": "B999",
                    "issue_text": "Potential issue",
                    "issue_severity": "LOW",
                    "filename": "app.py",
                    "cvss_vector": (
                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/"
                        "VA:H/SC:H/SI:H/SA:N"
                    ),
                    "cvss_score": 0.0,
                }
            ]
        }
    )
    result = ScanResult(ScanStatus.SUCCEEDED, findings=findings)

    adapted = to_security_findings(result)[0]

    assert adapted["severity"] == "critical"
    assert adapted["cvss_score"] == 9.9
    assert adapted["cvss_version"] == "4.0"
    assert adapted["cvss_calculated"] is True
    assert adapted["cvss_vector"] == findings[0].cvss_vector


def test_calculates_vectors_with_threat_and_environmental_metrics():
    finding = Finding(
        "B999",
        "Potential issue",
        "HIGH",
        "app.py",
        cvss_vector=(
            "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/SC:H/SI:H/"
            "AU:N/SA:N/S:N/R:A/V:C/RE:M/U:Green/MAV:L/MAC:L/MAT:P/MPR:L/"
            "MUI:A/MVC:N/MVI:L/MVA:H/MSC:L/MSI:N/MSA:S/CR:L/IR:L/AR:M/E:P"
        ),
    )
    result = ScanResult(ScanStatus.SUCCEEDED, findings=[finding])

    adapted = to_security_findings(result)[0]

    assert adapted["cvss_score"] == 3.5
    assert adapted["severity"] == "low"
    assert adapted["cvss_calculated"] is True
    assert "/E:P/" in adapted["cvss_vector"]
    assert "/MAV:L/" in adapted["cvss_vector"]


def test_invalid_or_incomplete_vectors_do_not_create_cvss_ratings():
    result = ScanResult(
        ScanStatus.SUCCEEDED,
        findings=[
            Finding(
                "B999",
                "Potential issue",
                "LOW",
                "app.py",
                cvss_vector="CVSS:4.0/AV:N/AC:L",
            ),
            Finding(
                "B998",
                "Malformed vector",
                "MEDIUM",
                "other.py",
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:J",
            ),
        ],
    )

    adapted = to_security_findings(result)

    assert [item["severity"] for item in adapted] == ["low", "medium"]
    assert all("cvss_score" not in item for item in adapted)
    assert all("cvss_calculated" not in item for item in adapted)


def test_informational_findings_never_receive_cvss_scores():
    result = ScanResult(
        ScanStatus.SUCCEEDED,
        findings=[
            Finding(
                "INFO",
                "Route discovered",
                "INFORMATIONAL",
                "app.py",
                cvss_vector=(
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/"
                    "VA:H/SC:H/SI:H/SA:N"
                ),
            )
        ],
    )

    adapted = to_security_findings(result)[0]

    assert adapted["severity"] == "informational"
    assert "cvss_score" not in adapted
    assert "cvss_calculated" not in adapted
