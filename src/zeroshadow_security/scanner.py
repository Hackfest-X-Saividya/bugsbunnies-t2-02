"""Safe Bandit subprocess execution."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .models import ScanResult, ScanStatus, ScannerError
from .normalize import normalize_bandit_results

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
EXCLUDED_NAMES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist"}


def _python_files(root: Path, max_files: int, max_file_bytes: int) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in EXCLUDED_NAMES for part in path.parts):
            continue
        if path.is_file() and path.stat().st_size <= max_file_bytes:
            files.append(path)
            if len(files) > max_files:
                raise ValueError(f"project contains more than {max_files} eligible Python files")
    return files


def run_bandit(
    target: str | Path,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    executable: str | None = None,
) -> ScanResult:
    started = time.monotonic()
    root = Path(target).expanduser().resolve()
    if not root.exists():
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Scan path does not exist", "invalid_path")])
    if not root.is_dir():
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Scan path must be a directory", "invalid_path")])

    try:
        files = _python_files(root, max_files, max_file_bytes)
    except (OSError, ValueError) as exc:
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError(str(exc), "invalid_project")])
    if not files:
        return ScanResult(ScanStatus.SUCCEEDED, duration_ms=_elapsed_ms(started), files_scanned=0)

    # Keep the default analyzer tied to the backend interpreter, not a separate PATH entry.
    command_prefix = [sys.executable, "-m", "bandit"] if executable is None else [executable]
    command = [
        *command_prefix,
        "-r",
        str(root),
        "-f",
        "json",
        "--quiet",
        "--exclude",
        ",".join(sorted(EXCLUDED_NAMES)),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
    except FileNotFoundError:
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Bandit executable was not found", "missing_executable")], files_scanned=len(files))
    except subprocess.TimeoutExpired as exc:
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Bandit scan timed out", "timeout", str(exc))], files_scanned=len(files))
    except OSError as exc:
        return ScanResult(ScanStatus.FAILED, errors=[ScannerError("Bandit could not be started", "execution_error", str(exc))], files_scanned=len(files))

    try:
        payload: Any = json.loads(completed.stdout or "{}")
        if not isinstance(payload, dict):
            raise ValueError("Bandit output must be a JSON object")
        findings = normalize_bandit_results(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        return ScanResult(
            ScanStatus.FAILED,
            errors=[ScannerError("Bandit returned malformed JSON", "malformed_output", str(exc))],
            exit_code=completed.returncode,
            duration_ms=_elapsed_ms(started),
            files_scanned=len(files),
        )

    errors = [ScannerError("Bandit reported an execution error", "scanner_error", completed.stderr.strip() or None)] if completed.returncode not in (0, 1) else []
    return ScanResult(
        ScanStatus.FAILED if errors else ScanStatus.SUCCEEDED,
        findings=findings,
        errors=errors,
        exit_code=completed.returncode,
        duration_ms=_elapsed_ms(started),
        files_scanned=len(files),
    )


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)
