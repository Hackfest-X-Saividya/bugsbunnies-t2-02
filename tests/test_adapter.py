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
