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
        assert row["status"] == "approved"
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
