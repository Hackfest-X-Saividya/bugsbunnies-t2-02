import subprocess

from zeroshadow_security import (
    Finding,
    ScanStatus,
    accepted_extensions,
    language_for_path,
    scan_project,
)
from zeroshadow_security.analyzers import SemgrepAnalyzer
from zeroshadow_security.normalize import normalize_semgrep_results


def test_supported_extensions_are_routed_without_case_sensitivity():
    assert ".py" in accepted_extensions()
    assert language_for_path("src/App.TSX") == "typescript"
    assert language_for_path("README.md") is None


def test_python_project_preserves_bandit_analysis(tmp_path):
    (tmp_path / "app.py").write_text("password = 'example-only'\n", encoding="utf-8")
    result = scan_project(tmp_path)
    assert result.status is ScanStatus.SUCCEEDED
    assert result.files_scanned == 1
    assert result.findings[0].analyzer == "bandit"
    assert result.findings[0].language == "python"


def test_non_python_project_is_explicitly_unavailable_without_semgrep(tmp_path):
    (tmp_path / "app.js").write_text("const value = userInput;\n", encoding="utf-8")
    result = scan_project(tmp_path, semgrep_executable="missing-semgrep")
    assert result.status is ScanStatus.FAILED
    assert result.errors[0].kind == "analyzer_unavailable"
    assert result.findings == []


def test_semgrep_results_normalize_to_common_findings():
    findings = normalize_semgrep_results(
        {
            "results": [
                {
                    "check_id": "javascript.lang.security.audit.test",
                    "path": "app.js",
                    "start": {"line": 4},
                    "extra": {
                        "message": "Unsafe operation",
                        "severity": "WARNING",
                        "lines": "dangerous(input)",
                    },
                }
            ]
        }
    )
    assert findings[0].rule_id == "javascript.lang.security.audit.test"
    assert findings[0].severity == "WARNING"
    assert findings[0].line == 4
    assert findings[0].language == "javascript"
    assert findings[0].analyzer == "semgrep"


def test_semgrep_timeout_and_malformed_output_are_structured(tmp_path, monkeypatch):
    source = tmp_path / "app.js"
    source.write_text("const x = 1;\n", encoding="utf-8")
    analyzer = SemgrepAnalyzer(executable="semgrep")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timeout)
    timed_out = analyzer.analyze(tmp_path, [source], timeout_seconds=0.01)
    assert timed_out.errors[0].kind == "analyzer_timeout"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "{", ""),
    )
    malformed = analyzer.analyze(tmp_path, [source], timeout_seconds=1)
    assert malformed.errors[0].kind == "malformed_analyzer_output"
