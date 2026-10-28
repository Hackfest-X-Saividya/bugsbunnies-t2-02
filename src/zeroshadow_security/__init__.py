"""ZeroShadow AI security intelligence primitives."""

from .adapter import to_security_errors, to_security_findings
from .analyzers import SUPPORTED_EXTENSIONS, accepted_extensions, language_for_path, scan_project
from .malware import (
    ArchiveInspection,
    ArchiveValidationError,
    ClamAVScanner,
    MalwareScanResult,
    MalwareScanStatus,
    MalwareScanner,
    QuarantineRecord,
    UploadLimits,
    cleanup_upload_artifacts,
    inspect_archive,
    inspect_upload_path,
    quarantine_upload,
    should_block_scan,
)
from .mappings import assess_finding_risk, normalize_risk_level, risk_priority
from .models import Finding, ScanResult, ScanStatus, ScannerError
from .review import (
    InMemoryAuthorizationPolicy,
    InMemoryNotificationSink,
    InMemoryReviewRepository,
    ManagerReviewService,
    Notification,
    UploadReview,
)
from .risk import assess_risk, sort_findings_by_priority, summarize_risk_levels
from .service import SecurityIntelligenceService
from .upload_formats import (
    CONFIGURATION,
    DEPENDENCY_MANIFEST,
    PROJECT_ARCHIVE,
    SOURCE,
    SUPPLEMENTAL_DOCUMENT,
    UNSUPPORTED,
    UploadFileInfo,
    classify_filename,
    describe_file,
)
from .workflow import UploadScanWorkflow, UploadWorkflowResult

__all__ = [
    "Finding",
    "ScanResult",
    "ScanStatus",
    "ScannerError",
    "SecurityIntelligenceService",
    "SUPPORTED_EXTENSIONS",
    "accepted_extensions",
    "language_for_path",
    "scan_project",
    "ArchiveInspection",
    "ArchiveValidationError",
    "ClamAVScanner",
    "MalwareScanResult",
    "MalwareScanStatus",
    "MalwareScanner",
    "QuarantineRecord",
    "UploadLimits",
    "ManagerReviewService",
    "InMemoryAuthorizationPolicy",
    "InMemoryNotificationSink",
    "InMemoryReviewRepository",
    "Notification",
    "UploadReview",
    "UploadScanWorkflow",
    "UploadWorkflowResult",
    "assess_finding_risk",
    "assess_risk",
    "cleanup_upload_artifacts",
    "inspect_archive",
    "inspect_upload_path",
    "normalize_risk_level",
    "quarantine_upload",
    "risk_priority",
    "should_block_scan",
    "sort_findings_by_priority",
    "summarize_risk_levels",
    "to_security_errors",
    "to_security_findings",
    "CONFIGURATION",
    "DEPENDENCY_MANIFEST",
    "PROJECT_ARCHIVE",
    "SOURCE",
    "SUPPLEMENTAL_DOCUMENT",
    "UNSUPPORTED",
    "UploadFileInfo",
    "classify_filename",
    "describe_file",
]
