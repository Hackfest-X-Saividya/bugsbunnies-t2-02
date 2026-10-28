"""Language analyzer registry with conservative optional-tool handling."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

from .models import Finding, ScanResult, ScanStatus, ScannerError
from .normalize import normalize_semgrep_results
from .scanner import run_bandit


SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
}

SEMgrep_LANGUAGES = frozenset(set(SUPPORTED_EXTENSIONS.values()) - {"python"})
EXCLUDED_NAMES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist", "node_modules"}


def accepted_extensions() -> tuple[str, ...]:
    return tuple(sorted(SUPPORTED_EXTENSIONS))


def language_for_path(path: str | Path) -> str | None:
    return SUPPORTED_EXTENSIONS.get(Path(path).suffix.lower())


class Analyzer(Protocol):
    def analyze(self, root: Path, files: list[Path], *, timeout_seconds: float) -> ScanResult:
        """Analyze only the supplied files without executing source code."""


@dataclass(frozen=True)
class AnalyzerRegistry:
    python: Analyzer
    semgrep: Analyzer

    def analyze(
        self,
        root: Path,
        files: Iterable[Path],
        *,
        timeout_seconds: float = 60,
    ) -> ScanResult:
        grouped: dict[str, list[Path]] = {}
        for path in files:
            language = language_for_path(path)
            if language is not None:
                grouped.setdefault(language, []).append(path)

        results: list[ScanResult] = []
        if grouped.get("python"):
            results.append(self.python.analyze(root, grouped["python"], timeout_seconds=timeout_seconds))
        for language in sorted(set(grouped) - {"python"}):
            results.append(self.semgrep.analyze(root, grouped[language], timeout_seconds=timeout_seconds))

        if not results:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("No supported source files were supplied.", "no_supported_files")],
            )
        findings = [finding for result in results for finding in result.findings]
        errors = [error for result in results for error in result.errors]
        files_scanned = sum(result.files_scanned for result in results)
        if errors and files_scanned:
            status = ScanStatus.PARTIAL
        elif errors:
            status = ScanStatus.FAILED
        else:
            status = ScanStatus.SUCCEEDED
        return ScanResult(status, findings=findings, errors=errors, files_scanned=files_scanned)


class BanditAnalyzer:
    def __init__(self, *, executable: str = "bandit", max_files: int = 10_000, max_file_bytes: int = 5 * 1024 * 1024) -> None:
        self.executable = executable
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

    def analyze(self, root: Path, files: list[Path], *, timeout_seconds: float) -> ScanResult:
        # Bandit scans the project root; the registry only invokes it when Python files exist.
        return run_bandit(
            root,
            timeout_seconds=timeout_seconds,
            max_files=self.max_files,
            max_file_bytes=self.max_file_bytes,
            executable=self.executable,
        )


class SemgrepAnalyzer:
    def __init__(self, *, executable: str = "semgrep", max_output_bytes: int = 5 * 1024 * 1024) -> None:
        self.executable = executable
        self.max_output_bytes = max_output_bytes

    def analyze(self, root: Path, files: list[Path], *, timeout_seconds: float) -> ScanResult:
        started = time.monotonic()
        command = [
            self.executable,
            "--json",
            "--config",
            "auto",
            "--no-git-ignore",
            "--quiet",
            *[str(path) for path in files],
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=timeout_seconds,
            )
        except FileNotFoundError:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("Optional Semgrep analyzer is unavailable.", "analyzer_unavailable", "Install Semgrep to analyze non-Python source.")],
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("Optional analyzer timed out.", "analyzer_timeout")],
            )
        except OSError as exc:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("Optional analyzer could not be started.", "analyzer_execution_error", str(exc))],
            )

        output = completed.stdout or ""
        if len(output.encode("utf-8", errors="replace")) > self.max_output_bytes:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("Optional analyzer output exceeded the configured limit.", "analyzer_output_too_large")],
            )
        try:
            payload = json.loads(output or "{}")
            findings = normalize_semgrep_results(
                payload,
                language=language_for_path(files[0]) if files else None,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            return ScanResult(
                ScanStatus.FAILED,
                errors=[ScannerError("Optional analyzer returned malformed output.", "malformed_analyzer_output", str(exc))],
            )
        errors = []
        if completed.returncode not in (0, 1):
            errors.append(ScannerError("Optional analyzer reported an execution error.", "analyzer_error"))
        return ScanResult(
            ScanStatus.FAILED if errors else ScanStatus.SUCCEEDED,
            findings=findings,
            errors=errors,
            exit_code=completed.returncode,
            duration_ms=round((time.monotonic() - started) * 1000),
            files_scanned=len(files),
        )


def default_analyzer_registry(
    *,
    bandit_executable: str = "bandit",
    semgrep_executable: str = "semgrep",
) -> AnalyzerRegistry:
    return AnalyzerRegistry(
        python=BanditAnalyzer(executable=bandit_executable),
        semgrep=SemgrepAnalyzer(executable=semgrep_executable),
    )


def scan_project(
    target: str | Path,
    *,
    timeout_seconds: float = 60,
    bandit_executable: str = "bandit",
    semgrep_executable: str = "semgrep",
    executable: str | None = None,
) -> ScanResult:
    root = Path(target).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Scan path must be an existing directory.", "invalid_path")])
    files = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_NAMES for part in path.parts)
        and language_for_path(path) is not None
    ]
    return default_analyzer_registry(
        bandit_executable=executable or bandit_executable,
        semgrep_executable=semgrep_executable,
    ).analyze(root, files, timeout_seconds=timeout_seconds)
