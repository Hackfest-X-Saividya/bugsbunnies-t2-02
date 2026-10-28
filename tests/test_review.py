import pytest

from zeroshadow_security.review import (
    InMemoryAuthorizationPolicy,
    InMemoryNotificationSink,
    ManagerReviewService,
)


def test_manager_review_flow_and_notifications():
    service = ManagerReviewService(authorization=InMemoryAuthorizationPolicy({"manager-1"}))
    review = service.create_review(
        upload_id="u-1",
        uploader_id="user-1",
        detection_reasons=["possible malware"],
        quarantine_path="/tmp/quarantine/u-1.zip",
        metadata={"scanner": "clamscan"},
        requested_by="user-1",
    )
    assert review.status == "pending"
    pending = service.list_pending_reviews(actor_id="manager-1", actor_role="manager")
    assert len(pending) == 1
    uploader_view = service.get_review(review_id=review.review_id, actor_id="user-1", actor_role="user")
    assert uploader_view.review_id == review.review_id
    assert uploader_view.detection_reasons == []
    assert uploader_view.quarantine_path is None

    approved = service.approve(
        review_id=review.review_id,
        actor_id="manager-1",
        actor_role="manager",
        reason="Files are clean after static review and no executable content is allowed.",
    )
    assert approved.status == "approved"
    assert approved.metadata["execution_allowed"] is False
    assert service.notifications_for("user-1")


def test_self_approval_and_manager_authorization_are_rejected():
    service = ManagerReviewService(authorization=InMemoryAuthorizationPolicy({"manager-1"}))
    review = service.create_review(upload_id="u-2", uploader_id="user-2", detection_reasons=["suspicious zip"])

    with pytest.raises(PermissionError):
        service.approve(review_id=review.review_id, actor_id="user-2", actor_role="user", reason="bad")

    with pytest.raises(PermissionError):
        service.list_pending_reviews(actor_id="user-2", actor_role="user")

    with pytest.raises(ValueError):
        service.approve(review_id=review.review_id, actor_id="manager-1", actor_role="manager", reason="   ")


def test_review_decision_reasons_and_audit_history_are_recorded():
    service = ManagerReviewService(authorization=InMemoryAuthorizationPolicy({"manager-1"}))
    review = service.create_review(upload_id="u-3", uploader_id="user-3", detection_reasons=["archive bomb"])
    service.reject(review_id=review.review_id, actor_id="manager-1", actor_role="manager", reason="malware evidence")
    assert review.decision == "rejected"
    assert "manager-1" in review.audit_history[1]
    assert review.decision_reason.strip() == "malware evidence"


def test_uploader_status_hides_sensitive_details():
    service = ManagerReviewService(authorization=InMemoryAuthorizationPolicy({"manager-1"}))
    review = service.create_review(upload_id="u-4", uploader_id="user-4", detection_reasons=["zip traversal"])
    service.request_further_review(review_id=review.review_id, actor_id="manager-1", actor_role="manager", reason="Need more evidence")
    status = service.uploader_status(uploader_id="user-4", upload_id="u-4")
    assert status["status"] == "more_info_requested"
    assert "quarantined" in status


def test_invalid_review_transition_is_rejected():
    service = ManagerReviewService(
        authorization=InMemoryAuthorizationPolicy({"manager-1"})
    )
    review = service.create_review(upload_id="u-5", uploader_id="user-5")
    service.reject(review_id=review.review_id, actor_id="manager-1", reason="blocked")

    with pytest.raises(ValueError):
        service.approve(review_id=review.review_id, actor_id="manager-1", reason="approve")


def test_notification_sink_failures_are_not_silenced():
    class BrokenSink:
        def send(self, notification):
            raise RuntimeError("notification service unavailable")

    service = ManagerReviewService(
        authorization=InMemoryAuthorizationPolicy({"manager-1"}),
        notifications=BrokenSink(),
    )
    review = service.create_review(upload_id="u-6", uploader_id="user-6")

    with pytest.raises(RuntimeError, match="notification service unavailable"):
        service.reject(review_id=review.review_id, actor_id="manager-1", reason="blocked")
