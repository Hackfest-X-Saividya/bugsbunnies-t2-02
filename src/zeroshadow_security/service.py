"""Application-facing security intelligence service."""

from pathlib import Path

from .models import ScanResult
from .scanner import run_bandit
from .analyzers import scan_project


class SecurityIntelligenceService:
    """Callable facade kept independent from any unavailable public API contract."""

    def scan(self, target: str | Path, **options: object) -> ScanResult:
        return scan_project(target, **options)

    def scan_python(self, target: str | Path, **options: object) -> ScanResult:
        return run_bandit(target, **options)
