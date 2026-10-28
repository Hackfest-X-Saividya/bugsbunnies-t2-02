import io
import zipfile

import pytest

from zeroshadow_security import (
    InMemoryAuthorizationPolicy,
    MalwareScanResult,
    MalwareScanStatus,
    ManagerReviewService,
    ScanResult,
    ScanStatus,
    UploadLimits,
    UploadScanWorkflow,
)


class FakeScanner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def scan(self, path, *, timeout_seconds):
        self.calls.append((path, timeout_seconds))
        return self.result


def archive_bytes(*entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def clean_static_scan(path):
    assert (path / "app.py").read_text(encoding="utf-8") == "print('safe')\n"
    return ScanResult(ScanStatus.SUCCEEDED, files_scanned=1)


def test_clean_archive_runs_static_analysis():
    scanner = FakeScanner(MalwareScanResult(MalwareScanStatus.CLEAN, "clean"))
    workflow = UploadScanWorkflow(scanner=scanner, static_scanner=clean_static_scan)

    result = workflow.submit_archive(
        archive_bytes(("app.py", "print('safe')\n")),
        upload_id="upload-1",
        uploader_id="user-1",
    )

    assert result.inspection.status == MalwareScanStatus.CLEAN
    assert result.scan_allowed
    assert result.scan.status is ScanStatus.SUCCEEDED
    assert result.review is None


@pytest.mark.parametrize(
    "scan_result",
    [
        MalwareScanResult(MalwareScanStatus.SUSPICIOUS, "scanner heuristic"),
        MalwareScanResult(MalwareScanStatus.MALWARE_DETECTED, "signature match"),
        MalwareScanResult(MalwareScanStatus.UNAVAILABLE, "scanner failed"),
    ],
)
def test_non_clean_results_are_quarantined_and_block_static_analysis(tmp_path, scan_result):
    scanner = FakeScanner(scan_result)
    workflow = UploadScanWorkflow(
        scanner=scanner,
        quarantine_root=tmp_path / "quarantine",
        static_scanner=lambda path: pytest.fail("static analysis bypassed"),
    )

    result = workflow.submit_archive(
        archive_bytes(("app.py", "print('safe')\n")),
        upload_id="upload-blocked",
        uploader_id="user-1",
    )

    assert result.scan is None
    assert result.review is not None
    assert result.inspection.quarantined
    assert result.inspection.quarantine_path
    assert not result.scan_allowed


def test_approval_is_required_before_approved_archive_can_be_scanned(tmp_path):
    scanner = FakeScanner(MalwareScanResult(MalwareScanStatus.SUSPICIOUS, "needs review"))
    reviews = ManagerReviewService(
        authorization=InMemoryAuthorizationPolicy({"manager-1"})
    )
    workflow = UploadScanWorkflow(
        scanner=scanner,
        review_service=reviews,
        quarantine_root=tmp_path / "quarantine",
        static_scanner=lambda path: ScanResult(ScanStatus.SUCCEEDED, files_scanned=1),
    )
    result = workflow.submit_archive(
        archive_bytes(("app.py", "print('safe')\n")),
        upload_id="upload-review",
        uploader_id="user-1",
    )

    with pytest.raises(PermissionError):
        workflow.scan_approved(result.review.review_id)

    reviews.approve(
        review_id=result.review.review_id,
        actor_id="manager-1",
        reason="Permit static analysis only",
    )
    approved = workflow.scan_approved(result.review.review_id)
    assert approved.scan.status is ScanStatus.SUCCEEDED
    assert approved.inspection.status == MalwareScanStatus.CLEAN


def test_archive_limits_and_traversal_are_blocked(tmp_path):
    limits = UploadLimits(max_files=1, max_archive_depth=2)
    workflow = UploadScanWorkflow(
        scanner=FakeScanner(MalwareScanResult(MalwareScanStatus.CLEAN)),
        limits=limits,
        quarantine_root=tmp_path / "quarantine",
    )

    too_many = workflow.submit_archive(
        archive_bytes(("one.py", "x"), ("two.py", "y")),
        upload_id="upload-many",
        uploader_id="user-1",
    )
    traversal = workflow.submit_archive(
        archive_bytes(("../escape.py", "x")),
        upload_id="upload-traversal",
        uploader_id="user-1",
    )

    assert too_many.inspection.status == MalwareScanStatus.SUSPICIOUS
    assert traversal.inspection.status == MalwareScanStatus.SUSPICIOUS
    assert too_many.review is not None
    assert traversal.review is not None


def test_malformed_and_symlink_archives_are_blocked(tmp_path):
    workflow = UploadScanWorkflow(
        scanner=FakeScanner(MalwareScanResult(MalwareScanStatus.CLEAN)),
        quarantine_root=tmp_path / "quarantine",
    )
    malformed = workflow.submit_archive(
        b"not a zip",
        upload_id="upload-malformed",
        uploader_id="user-1",
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0xA000
        archive.writestr(info, "target")
    symlink = workflow.submit_archive(
        buffer.getvalue(),
        upload_id="upload-symlink",
        uploader_id="user-1",
    )

    assert malformed.inspection.status == MalwareScanStatus.SUSPICIOUS
    assert symlink.inspection.status == MalwareScanStatus.SUSPICIOUS
