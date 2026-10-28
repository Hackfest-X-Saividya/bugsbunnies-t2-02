import json
import subprocess

from zeroshadow_security import (
    Finding,
    ScanResult,
    ScanStatus,
    ScannerError,
    SecurityIntelligenceService,
)
from zeroshadow_security.scanner import run_bandit


def test_empty_project_is_success(tmp_path):
    result = run_bandit(tmp_path)
    assert result.status is ScanStatus.SUCCEEDED
    assert result.files_scanned == 0


def test_missing_path_is_failure(tmp_path):
    result = run_bandit(tmp_path / "missing")
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].kind == "invalid_path"


def test_missing_executable_is_failure(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    result = run_bandit(tmp_path, executable="not-a-real-bandit")
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].kind == "missing_executable"


def test_findings_do_not_make_a_scan_failure(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("password = 'secret'\n", encoding="utf-8")
    captured_command = []

    def fake_run(*args, **kwargs):
        captured_command.append(args[0])
        return subprocess.CompletedProcess(
            args[0],
            1,
            json.dumps({"results": [{"test_id": "B105", "filename": "app.py", "issue_severity": "LOW"}]}),
            "",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_bandit(tmp_path)
    assert result.status is ScanStatus.SUCCEEDED
    assert len(result.findings) == 1
    assert "--exclude" in captured_command[0]
    assert ".venv" in captured_command[0][captured_command[0].index("--exclude") + 1]


def test_malformed_output_is_failure(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "{", ""))
    result = run_bandit(tmp_path)
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].kind == "malformed_output"


def test_timeout_is_structured_failure(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run_bandit(tmp_path, timeout_seconds=0.01)
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].kind == "timeout"


def test_nonzero_execution_failure_is_not_a_finding(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "{}", "scanner failed"),
    )
    result = run_bandit(tmp_path)
    assert result.status is ScanStatus.FAILED
    assert result.findings == []
    assert result.errors[0].kind == "scanner_error"


def test_serialized_result_has_the_internal_contract_shape():
    result = ScanResult(
        status=ScanStatus.SUCCEEDED,
        findings=[Finding("B999", "Unknown test", "MEDIUM", "app.py")],
        errors=[ScannerError("none", "scanner_error")],
        exit_code=0,
        duration_ms=12,
        files_scanned=1,
    )
    serialized = result.to_internal_dict()
    assert set(serialized) == {
        "status",
        "findings",
        "errors",
        "exit_code",
        "duration_ms",
        "files_scanned",
    }
    assert set(serialized["findings"][0]) == {
        "rule_id",
        "description",
        "severity",
        "path",
        "line",
        "test_id",
        "evidence",
        "owasp_category",
        "remediation",
        "references",
    }
    assert serialized["findings"][0]["line"] is None
    assert serialized["errors"][0] == {
        "message": "none",
        "kind": "scanner_error",
        "details": None,
    }


def test_public_service_import_and_scan_signature():
    service = SecurityIntelligenceService()
    assert callable(service.scan)
