"""Unit tests for the persistent human-approval queue."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from darwaza.approval_queue import ApprovalQueue
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)


def _mandate() -> NormalizedMandate:
    return NormalizedMandate(
        mandate_id="m1",
        principal_id="user-krishna",
        expiry=FUTURE,
        signature="sig",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )


def _decision() -> Decision:
    return Decision(
        outcome=Outcome.NEEDS_HUMAN, reason="over threshold", failed_check="human_review_threshold"
    )


def test_enqueue_then_appears_in_pending(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation text")

        pending = queue.list_pending()
        assert len(pending) == 1
        assert pending[0]["id"] == request_id
        assert pending[0]["mandate_id"] == "m1"
    finally:
        queue.close()


def test_resolve_approved_removes_from_pending(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")

        queue.resolve(request_id, approved=True)

        assert queue.list_pending() == []
        row = queue.get(request_id)
        # Stage 6: approval alone is not terminal any more -- see
        # approval_queue.py's module docstring and
        # test_defect_hunt.test_approved_status_does_not_distinguish_
        # execution_from_a_crash. Execution against Razorpay hasn't
        # happened yet, so the status must say so.
        assert row["status"] == "approved_pending_execution"
    finally:
        queue.close()


def test_mark_executed_transitions_from_approved_pending_execution(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")
        queue.resolve(request_id, approved=True)

        queue.mark_executed(request_id, razorpay_order_id="order_abc123")

        row = queue.get(request_id)
        assert row["status"] == "executed"
        assert row["razorpay_order_id"] == "order_abc123"
    finally:
        queue.close()


def test_mark_executed_refuses_from_a_status_other_than_approved_pending_execution(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")
        # Still 'pending' -- no human has approved this yet.
        with pytest.raises(ValueError):
            queue.mark_executed(request_id, razorpay_order_id="order_abc123")

        queue.resolve(request_id, approved=True)
        queue.mark_executed(request_id, razorpay_order_id="order_abc123")
        # Already 'executed' -- a second mark_executed() must not succeed
        # silently (this is exactly what prevents two racing retries
        # from both thinking they won).
        with pytest.raises(ValueError):
            queue.mark_executed(request_id, razorpay_order_id="order_xyz789")
    finally:
        queue.close()


def test_record_execution_failure_keeps_status_retryable(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")
        queue.resolve(request_id, approved=True)

        queue.record_execution_failure(request_id, error="RAZORPAY_KEY_ID not set")
        queue.record_execution_failure(request_id, error="RAZORPAY_KEY_ID not set")

        row = queue.get(request_id)
        assert row["status"] == "approved_pending_execution"
        assert row["execution_attempts"] == 2
        assert row["last_execution_error"] == "RAZORPAY_KEY_ID not set"
    finally:
        queue.close()


def test_list_pending_execution_shows_approved_not_yet_executed_rows(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        pending_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")
        approved_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")
        executed_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")

        queue.resolve(approved_id, approved=True)
        queue.resolve(executed_id, approved=True)
        queue.mark_executed(executed_id, razorpay_order_id="order_done")

        ids = [row["id"] for row in queue.list_pending_execution()]
        assert ids == [approved_id]
        assert pending_id not in ids
        assert executed_id not in ids
    finally:
        queue.close()


def test_resolve_twice_raises(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
        request_id = queue.enqueue(_mandate(), tx, _decision(), "explanation")

        queue.resolve(request_id, approved=False)
        with pytest.raises(ValueError):
            queue.resolve(request_id, approved=True)
    finally:
        queue.close()


def test_resolve_unknown_id_raises(tmp_path):
    queue = ApprovalQueue(tmp_path / "approvals.db")
    try:
        with pytest.raises(ValueError):
            queue.resolve("does-not-exist", approved=True)
    finally:
        queue.close()


def test_persists_across_separate_instances(tmp_path):
    db_path = tmp_path / "approvals.db"
    tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")

    first = ApprovalQueue(db_path)
    request_id = first.enqueue(_mandate(), tx, _decision(), "explanation")
    first.close()

    second = ApprovalQueue(db_path)
    try:
        pending = second.list_pending()
        assert len(pending) == 1
        assert pending[0]["id"] == request_id
    finally:
        second.close()
