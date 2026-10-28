"""Package-level upload, malware, review-gated static-scan workflow."""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .malware import (
    ArchiveValidationError,
    MalwareScanResult,
    MalwareScanner,
    MalwareScanStatus,
    UploadLimits,
    DEFAULT_UPLOAD_LIMITS,
    inspect_archive,
    inspect_upload_path,
    cleanup_upload_artifacts,
)
from .models import ScanResult
from .review import ManagerReviewService, UploadReview
from .scanner import run_bandit


StaticScanner = Callable[[Path], ScanResult]


@dataclass(frozen=True)
class UploadWorkflowResult:
    inspection: MalwareScanResult
    scan: ScanResult | None = None
    review: UploadReview | None = None

    @property
    def scan_allowed(self) -> bool:
        return self.scan is not None


class UploadScanWorkflow:
    """Accept an archive, inspect it, and only scan clean or approved content."""

    def __init__(
        self,
        *,
        scanner: MalwareScanner | None = None,
        review_service: ManagerReviewService | None = None,
        static_scanner: StaticScanner | None = None,
        limits: UploadLimits = DEFAULT_UPLOAD_LIMITS,
        quarantine_root: str | Path | None = None,
    ) -> None:
        self.scanner = scanner
        self.review_service = review_service or ManagerReviewService()
        self.static_scanner = static_scanner or (lambda path: run_bandit(path))
        self.limits = limits
        self.quarantine_root = Path(quarantine_root) if quarantine_root else None

    def submit_archive(
        self,
        source: str | Path | bytes,
        *,
        upload_id: str,
        uploader_id: str,
    ) -> UploadWorkflowResult:
        with tempfile.TemporaryDirectory(prefix="zeroshadow-upload-") as workdir:
            staged = self._stage(source, Path(workdir) / "upload.zip")
            inspection = inspect_upload_path(
                staged,
                scanner=self.scanner,
                limits=self.limits,
                quarantine_root=self.quarantine_root,
            )
            if inspection.status != MalwareScanStatus.CLEAN:
                review = self.review_service.create_review(
                    upload_id=upload_id,
                    uploader_id=uploader_id,
                    detection_reasons=[inspection.reason or inspection.status],
                    quarantine_path=inspection.quarantine_path,
                    metadata={"malware_status": inspection.status, "scanner": inspection.scanner},
                    requested_by=uploader_id,
                )
                return UploadWorkflowResult(inspection=inspection, review=review)

            extracted = Path(workdir) / "project"
            self._extract_safely(staged, extracted)
            scan = self.static_scanner(extracted)
            return UploadWorkflowResult(inspection=inspection, scan=scan)

    def scan_approved(self, review_id: str) -> UploadWorkflowResult:
        review = self.review_service.repository.get(review_id)
        if review.status != "approved" or review.metadata.get("execution_allowed") is not False:
            raise PermissionError("Static analysis requires an approved review with execution disabled")
        if not review.quarantine_path:
            raise ValueError("Approved review has no quarantined archive")

        archive = Path(review.quarantine_path)
        if not archive.is_file():
            raise FileNotFoundError("Quarantined archive is unavailable")
        inspection = inspect_archive(archive, self.limits)
        with tempfile.TemporaryDirectory(prefix="zeroshadow-approved-") as workdir:
            extracted = Path(workdir) / "project"
            self._extract_safely(archive, extracted)
            scan = self.static_scanner(extracted)
        result = MalwareScanResult(
            MalwareScanStatus.CLEAN,
            reason="approved for static analysis only",
            scanner=inspection.files and "review-approved" or None,
            uploaded_files=list(inspection.files),
            quarantined=True,
            quarantine_path=str(archive),
        )
        return UploadWorkflowResult(inspection=result, scan=scan, review=review)

    @staticmethod
    def _stage(source: str | Path | bytes, destination: Path) -> Path:
        if isinstance(source, bytes):
            destination.write_bytes(source)
        else:
            source_path = Path(source)
            if not source_path.is_file():
                raise FileNotFoundError("Uploaded archive does not exist")
            shutil.copyfile(source_path, destination)
        return destination

    def _extract_safely(self, archive: Path, destination: Path) -> None:
        try:
            inspection = inspect_archive(archive, self.limits)
        except ArchiveValidationError:
            raise
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        root = destination.resolve()
        try:
            with zipfile.ZipFile(archive) as handle:
                for entry in handle.infolist():
                    if entry.is_dir():
                        continue
                    target = (destination / entry.filename).resolve()
                    if root not in target.parents:
                        raise ArchiveValidationError(f"archive extraction escaped destination: {entry.filename}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with handle.open(entry) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output, length=64 * 1024)
        except Exception:
            cleanup_upload_artifacts(destination)
            raise
        if len(inspection.files) > self.limits.max_files:
            cleanup_upload_artifacts(destination)
            raise ArchiveValidationError("archive contains too many files")
