"""Development review primitives with injectable authorization and delivery."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Protocol


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthorizationPolicy(Protocol):
    def require_manager(self, actor_id: str | None) -> None:
        """Raise PermissionError unless actor_id is an authorized manager."""


class NotificationSink(Protocol):
    def send(self, notification: "Notification") -> None:
        """Deliver a notification or raise an explicit delivery error."""


class ReviewRepository(Protocol):
    def save(self, review: "UploadReview") -> None: ...

    def get(self, review_id: str) -> "UploadReview": ...

    def all(self) -> list["UploadReview"]: ...


class InMemoryAuthorizationPolicy:
    """Test/development policy; production must use authenticated identity data."""

    def __init__(self, manager_ids: set[str] | frozenset[str] = frozenset()) -> None:
        self.manager_ids = frozenset(manager_ids)

    def require_manager(self, actor_id: str | None) -> None:
        if actor_id not in self.manager_ids:
            raise PermissionError("Manager authorization required for review operations")


class InMemoryReviewRepository:
    """Non-durable repository for local development and tests only."""

    def __init__(self) -> None:
        self._reviews: dict[str, UploadReview] = {}

    def save(self, review: "UploadReview") -> None:
        self._reviews[review.review_id] = review

    def get(self, review_id: str) -> "UploadReview":
        try:
            return self._reviews[review_id]
        except KeyError as exc:
            raise KeyError(f"Unknown review: {review_id}") from exc

    def all(self) -> list["UploadReview"]:
        return list(self._reviews.values())


@dataclass(frozen=True)
class Notification:
    recipient: str
    title: str
    message: str
    created_at: str = field(default_factory=utc_now)
    kind: str = "in_app"


class InMemoryNotificationSink:
    """Non-durable notification sink for local development and tests only."""

    def __init__(self) -> None:
        self.notifications: list[Notification] = []

    def send(self, notification: Notification) -> None:
        self.notifications.append(notification)


@dataclass
class UploadReview:
    review_id: str
    upload_id: str
    uploader_id: str
    detection_reasons: list[str] = field(default_factory=list)
    quarantine_path: str | None = None
    status: str = "pending"
    decision: str | None = None
    decision_reason: str | None = None
    requested_by: str | None = None
    reviewer_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    audit_history: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_audit(self, message: str) -> None:
        self.audit_history.append(f"{utc_now()} {message}")
        self.updated_at = utc_now()


class ManagerReviewService:
    """Review state machine; repository, identity policy, and delivery are injected."""

    def __init__(
        self,
        *,
        repository: ReviewRepository | None = None,
        authorization: AuthorizationPolicy | None = None,
        notifications: NotificationSink | None = None,
        allow_dev_fallback: bool = False,
    ) -> None:
        if allow_dev_fallback:
            raise ValueError("Caller-supplied role fallback is not supported; inject an authorization policy")
        self.repository = repository or InMemoryReviewRepository()
        self.authorization = authorization or InMemoryAuthorizationPolicy()
        self.notifications = notifications or InMemoryNotificationSink()

    def _require_manager(self, actor_id: str | None) -> None:
        self.authorization.require_manager(actor_id)

    def create_review(
        self,
        *,
        upload_id: str,
        uploader_id: str,
        detection_reasons: list[str] | None = None,
        quarantine_path: str | None = None,
        metadata: dict[str, Any] | None = None,
        requested_by: str | None = None,
    ) -> UploadReview:
        review = UploadReview(
            review_id=f"review-{len(self.repository.all()) + 1}",
            upload_id=upload_id,
            uploader_id=uploader_id,
            detection_reasons=list(detection_reasons or []),
            quarantine_path=quarantine_path,
            requested_by=requested_by,
            metadata=dict(metadata or {}),
        )
        review.add_audit(f"review created for uploaded artifact {upload_id}")
        self.repository.save(review)
        return review

    def list_pending_reviews(self, *, actor_id: str | None, actor_role: str | None = None) -> list[UploadReview]:
        self._require_manager(actor_id)
        return [review for review in self.repository.all() if review.status in {"pending", "more_info_requested"}]

    def get_review(self, *, review_id: str, actor_id: str | None, actor_role: str | None = None) -> UploadReview:
        review = self.repository.get(review_id)
        if actor_id == review.uploader_id:
            return replace(
                review,
                detection_reasons=[],
                quarantine_path=None,
                metadata={"status": review.status, "decision": review.decision},
                audit_history=[],
            )
        self._require_manager(actor_id)
        return review

    def _decide(self, review: UploadReview, actor_id: str | None, reason: str, status: str) -> UploadReview:
        self._require_manager(actor_id)
        if not reason or not reason.strip():
            raise ValueError("Decision reason is required")
        if review.status not in {"pending", "more_info_requested"}:
            raise ValueError(f"Cannot decide review in {review.status} state")
        review.status = status
        review.decision = status
        review.decision_reason = reason.strip()
        review.reviewer_id = actor_id
        review.add_audit(f"{actor_id} set status={status}: {review.decision_reason}")
        self.repository.save(review)
        return review

    def approve(self, *, review_id: str, actor_id: str | None, reason: str, uploader_id: str | None = None, actor_role: str | None = None) -> UploadReview:
        review = self.repository.get(review_id)
        if actor_id == review.uploader_id or (uploader_id is not None and actor_id == uploader_id):
            raise PermissionError("Uploaders cannot approve their own suspicious uploads")
        review = self._decide(review, actor_id, reason, "approved")
        review.metadata.update({"approval_scope": "static_analysis_only", "execution_allowed": False})
        self.repository.save(review)
        self._notify(review.uploader_id, "Upload review approved", "Your upload was approved for static analysis only; execution is not allowed.")
        return review

    def reject(self, *, review_id: str, actor_id: str | None, reason: str, uploader_id: str | None = None, actor_role: str | None = None) -> UploadReview:
        review = self.repository.get(review_id)
        if actor_id == review.uploader_id or (uploader_id is not None and actor_id == uploader_id):
            raise PermissionError("Uploaders cannot reject their own suspicious uploads")
        review = self._decide(review, actor_id, reason, "rejected")
        review.metadata.update({"approval_scope": "blocked", "execution_allowed": False})
        self.repository.save(review)
        self._notify(review.uploader_id, "Upload review rejected", "Your suspicious upload was rejected and remains quarantined.")
        return review

    def request_further_review(self, *, review_id: str, actor_id: str | None, reason: str, actor_role: str | None = None) -> UploadReview:
        review = self._decide(review=self.repository.get(review_id), actor_id=actor_id, reason=reason, status="more_info_requested")
        self._notify(review.uploader_id, "Additional review required", "Your upload requires further review before static analysis may continue.")
        return review

    def _notify(self, recipient: str, title: str, message: str) -> None:
        self.notifications.send(Notification(recipient, title, message))

    def notifications_for(self, actor_id: str) -> list[Notification]:
        sink = self.notifications
        return [item for item in getattr(sink, "notifications", []) if item.recipient == actor_id]

    def uploader_status(self, *, uploader_id: str, upload_id: str) -> dict[str, Any]:
        review = next((item for item in self.repository.all() if item.upload_id == upload_id and item.uploader_id == uploader_id), None)
        if review is None:
            return {"status": "clean", "decision": None}
        return {
            "status": review.status,
            "decision": review.decision,
            "message": "Upload is quarantined pending review." if review.status in {"pending", "more_info_requested"} else "Upload review completed.",
            "quarantined": review.quarantine_path is not None,
        }
