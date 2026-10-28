"""Classification rules for files accepted by the upload boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analyzers import language_for_path


SOURCE = "source"
CONFIGURATION = "configuration"
DEPENDENCY_MANIFEST = "dependency manifest"
PROJECT_ARCHIVE = "project archive"
UNSUPPORTED = "unsupported"

_CONFIGURATION_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml"}
_DEPENDENCY_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "cargo.toml",
}
_CONFIGURATION_FILENAMES = {"dockerfile", "docker-compose.yml", "compose.yaml"}


@dataclass(frozen=True)
class UploadFileInfo:
    path: str
    classification: str
    language: str | None = None
    analyzer: str | None = None


def classify_filename(filename: str) -> str:
    name = Path(filename).name
    lowered = name.lower()
    if lowered.endswith(".zip"):
        return PROJECT_ARCHIVE
    if lowered.endswith(".env.example") or lowered in {".env.example", "dockerfile"}:
        return CONFIGURATION
    if lowered in _DEPENDENCY_FILENAMES:
        return DEPENDENCY_MANIFEST
    if lowered in _CONFIGURATION_FILENAMES or Path(name).suffix.lower() in _CONFIGURATION_EXTENSIONS:
        return CONFIGURATION
    if language_for_path(name) is not None:
        return SOURCE
    return UNSUPPORTED


def describe_file(path: str) -> UploadFileInfo:
    classification = classify_filename(path)
    language = language_for_path(path) if classification == SOURCE else None
    analyzer = "bandit" if language == "python" else "semgrep" if language else None
    return UploadFileInfo(path, classification, language, analyzer)


def is_safe_upload_name(filename: str) -> bool:
    lowered = Path(filename).name.lower()
    return lowered == ".env.example" or not lowered.startswith(".env") or lowered.endswith(".env.example")
