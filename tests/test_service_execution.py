"""Stage 6: service.py's execution-retry path -- execute_approval(),
resolve_approval()'s `status` field, and _attempt_execution()'s queue
bookkeeping. See approval_queue.py and razorpay_client.py for the two
lower layers this builds on (the 'approved_pending_execution' status,
and create_order()'s retry/idempotency-by-receipt), and
tests/test_defect_hunt.py's D6 tests for the crash scenario this whole
stage exists to fix.

No live Razorpay call anywhere in this file -- razorpay_client.create_
order() itself is monkeypatched, not exercised for real (that's
razorpay_client.py's own test file's job).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from darwaza import keys, razorpay_client, service
from darwaza.approval_queue import ApprovalQueue
from darwaza.schema import NormalizedMandate, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)


def _signed_mandate(mandate_id: str, **overrides) -> NormalizedMandate:
    defaults = dict(
        mandate_id=mandate_id,
        principal_id="p1",
        expiry=FUTURE,
        signature="placeholder",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )
    defaults.update(overrides)
    m = NormalizedMandate(**defaults)
    return m.model_copy(update={"signature": keys.sign(m.signing_payload())})


def _needs_human(mandate_id: str, *, amount: float, tmp_path):
    mandate = _signed_mandate(mandate_id, max_amount=1000.0)
    tx = ProposedTransaction(merchant_id="merchant-a", amount=amount, category="electronics")
    result = service.authorize(
        mandate,
        tx,
        log_path=tmp_path / "audit_log.jsonl",
        nonce_db_path=tmp_path / "nonces.db",
        approval_db_path=tmp_path / "approvals.db",
    )
    assert result.request_id is not None  # NEEDS_HUMAN, by construction (amount over threshold)
    return result.request_id


# ---------------------------------------------------------------------------
# resolve_approval()'s status field
# ---------------------------------------------------------------------------


def test_resolve_approval_status_is_executed_on_immediate_success(tmp_path, monkeypatch):
    monkeypatch.setattr(razorpay_client, "create_order", lambda *a, **k: {"id": "order_1"})
    request_id = _needs_human("svc-status-executed-1", amount=800.0, tmp_path=tmp_path)

    result = service.resolve_approval(
        request_id,
        approved=True,
        log_path=tmp_path / "audit_log.jsonl",
        approval_db_path=tmp_path / "approvals.db",
    )

    assert result.status == "executed"
    assert result.razorpay_order["id"] == "order_1"
    assert result.razorpay_error is None


def test_resolve_approval_status_is_approved_pending_execution_on_failure(tmp_path, monkeypatch):
    def _boom(*a, **k):
        raise razorpay_client.ExecutionError("simulated outage")

    monkeypatch.setattr(razorpay_client, "create_order", _boom)
    request_id = _needs_human("svc-status-pending-1", amount=800.0, tmp_path=tmp_path)

    result = service.resolve_approval(
        request_id,
        approved=True,
        log_path=tmp_path / "audit_log.jsonl",
        approval_db_path=tmp_path / "approvals.db",
    )

    assert result.status == "approved_pending_execution"
    assert result.razorpay_order is None
    assert "simulated outage" in result.razorpay_error


def test_resolve_approval_status_is_denied_on_deny(tmp_path):
    request_id = _needs_human("svc-status-denied-1", amount=800.0, tmp_path=tmp_path)

    result = service.resolve_approval(
        request_id,
        approved=False,
        log_path=tmp_path / "audit_log.jsonl",
        approval_db_path=tmp_path / "approvals.db",
    )

    assert result.status == "denied"
    assert result.razorpay_order is None
    assert result.razorpay_error is None


# ---------------------------------------------------------------------------
# execute_approval()
# ---------------------------------------------------------------------------


def test_execute_approval_retries_a_failed_immediate_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(
        razorpay_client, "create_order", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
    )
    request_id = _needs_human("svc-execute-retry-1", amount=800.0, tmp_path=tmp_path)
    approval_db_path = tmp_path / "approvals.db"

    resolution = service.resolve_approval(
        request_id, approved=True, log_path=tmp_path / "audit_log.jsonl", approval_db_path=approval_db_path
    )
    assert resolution.status == "approved_pending_execution"

    monkeypatch.setattr(razorpay_client, "create_order", lambda *a, **k: {"id": "order_after_retry"})
    result = service.execute_approval(request_id, approval_db_path=approval_db_path)

    assert result.executed is True
    assert result.razorpay_order["id"] == "order_after_retry"

    queue = ApprovalQueue(approval_db_path)
    row = queue.get(request_id)
    queue.close()
    assert row["status"] == "executed"
    assert row["execution_attempts"] == 1  # the one failed attempt inside resolve_approval()


def test_execute_approval_is_idempotent_once_already_executed(tmp_path, monkeypatch):
    calls = []

    def _create(*a, **k):
        calls.append(1)
        return {"id": "order_once"}

    monkeypatch.setattr(razorpay_client, "create_order", _create)
    request_id = _needs_human("svc-execute-idempotent-1", amount=800.0, tmp_path=tmp_path)
    approval_db_path = tmp_path / "approvals.db"

    service.resolve_approval(
        request_id, approved=True, log_path=tmp_path / "audit_log.jsonl", approval_db_path=approval_db_path
    )
    assert len(calls) == 1

    # A second, later execute() call on an already-executed request must
    # not call Razorpay again -- it just returns the stored result.
    result = service.execute_approval(request_id, approval_db_path=approval_db_path)

    assert result.executed is True
    assert result.razorpay_order["id"] == "order_once"
    assert len(calls) == 1


def test_execute_approval_unknown_id_raises_not_found(tmp_path):
    with pytest.raises(service.ApprovalNotFoundError):
        service.execute_approval("does-not-exist", approval_db_path=tmp_path / "approvals.db")


def test_execute_approval_on_a_never_approved_request_raises(tmp_path):
    request_id = _needs_human("svc-execute-not-approved-1", amount=800.0, tmp_path=tmp_path)

    with pytest.raises(service.ApprovalNotYetApprovedError):
        service.execute_approval(request_id, approval_db_path=tmp_path / "approvals.db")


def test_execute_approval_on_a_denied_request_raises(tmp_path):
    request_id = _needs_human("svc-execute-denied-1", amount=800.0, tmp_path=tmp_path)
    service.resolve_approval(
        request_id,
        approved=False,
        log_path=tmp_path / "audit_log.jsonl",
        approval_db_path=tmp_path / "approvals.db",
    )

    with pytest.raises(service.ApprovalNotYetApprovedError):
        service.execute_approval(request_id, approval_db_path=tmp_path / "approvals.db")


def test_list_pending_execution_reflects_a_failed_immediate_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(
        razorpay_client, "create_order", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
    )
    request_id = _needs_human("svc-list-pending-exec-1", amount=800.0, tmp_path=tmp_path)
    approval_db_path = tmp_path / "approvals.db"

    service.resolve_approval(
        request_id, approved=True, log_path=tmp_path / "audit_log.jsonl", approval_db_path=approval_db_path
    )

    rows = service.list_pending_execution(approval_db_path=approval_db_path)
    ids = [r["id"] for r in rows]
    assert request_id in ids
    row = next(r for r in rows if r["id"] == request_id)
    assert row["execution_attempts"] == 1
    assert "down" in row["last_execution_error"]
