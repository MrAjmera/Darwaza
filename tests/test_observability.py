"""Unit tests for observability.py, plus integration checks that
service.authorize()/resolve_approval() actually thread decision_id
through the audit entry and (for NEEDS_HUMAN) the approval queue row —
not just that observability.py's own primitives work in isolation.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from darwaza import keys, observability, service
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
    return m.model_copy(update={"signature": keys.sign(m.principal_id, m.signing_payload())})


# ---------------------------------------------------------------------------
# new_decision_id
# ---------------------------------------------------------------------------


def test_new_decision_id_is_a_valid_uuid():
    decision_id = observability.new_decision_id()
    uuid.UUID(decision_id)  # raises ValueError if not a valid UUID string


def test_new_decision_id_is_unique_per_call():
    ids = {observability.new_decision_id() for _ in range(100)}
    assert len(ids) == 100


# ---------------------------------------------------------------------------
# time_decision
# ---------------------------------------------------------------------------


def test_time_decision_measures_a_non_negative_duration():
    with observability.time_decision() as timer:
        pass
    assert timer["duration_ms"] >= 0.0


def test_time_decision_propagates_exceptions_and_still_records_duration():
    timer_ref = {}
    with pytest.raises(ValueError):
        with observability.time_decision() as timer:
            timer_ref["t"] = timer
            raise ValueError("boom")
    assert timer_ref["t"]["duration_ms"] >= 0.0


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def test_counters_snapshot_starts_zero_filled_by_outcome():
    counters = observability.Counters()
    snapshot = counters.snapshot()
    assert snapshot["by_outcome"] == {"ALLOW": 0, "DENY": 0, "NEEDS_HUMAN": 0}
    assert snapshot["by_failed_check"] == {}


def test_counters_record_aggregates_by_outcome_and_failed_check():
    counters = observability.Counters()
    counters.record("DENY", "amount_cap")
    counters.record("DENY", "amount_cap")
    counters.record("DENY", "expiry")
    counters.record("ALLOW", None)

    snapshot = counters.snapshot()
    assert snapshot["by_outcome"]["DENY"] == 3
    assert snapshot["by_outcome"]["ALLOW"] == 1
    assert snapshot["by_failed_check"]["amount_cap"] == 2
    assert snapshot["by_failed_check"]["expiry"] == 1
    assert "ALLOW" not in snapshot["by_failed_check"]  # None never becomes a key


def test_counters_reset_clears_everything():
    counters = observability.Counters()
    counters.record("DENY", "amount_cap")
    counters.reset()
    assert counters.snapshot()["by_outcome"]["DENY"] == 0


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------


def test_log_decision_emits_one_valid_json_line_with_expected_fields(caplog):
    caplog.set_level(logging.INFO, logger="darwaza")

    observability.log_decision(
        decision_id="test-decision-id",
        mandate_id="mandate-1",
        outcome="ALLOW",
        failed_check=None,
        evaluate_duration_ms=1.23,
        signature_verify_duration_ms=0.45,
        request_id=None,
    )

    assert len(caplog.records) == 1
    payload = json.loads(caplog.records[0].message)
    assert payload["event"] == "decision"
    assert payload["decision_id"] == "test-decision-id"
    assert payload["mandate_id"] == "mandate-1"
    assert payload["outcome"] == "ALLOW"
    assert payload["evaluate_duration_ms"] == 1.23


def test_log_decision_also_updates_counters(caplog):
    caplog.set_level(logging.INFO, logger="darwaza")
    before = observability.COUNTERS.snapshot()["by_outcome"]["ALLOW"]

    observability.log_decision(
        decision_id="x",
        mandate_id="m",
        outcome="ALLOW",
        failed_check=None,
        evaluate_duration_ms=0.1,
        signature_verify_duration_ms=0.1,
    )

    after = observability.COUNTERS.snapshot()["by_outcome"]["ALLOW"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# decision_id threaded through service.authorize()/resolve_approval()
# ---------------------------------------------------------------------------


def test_authorize_threads_decision_id_into_the_audit_entry(tmp_path):
    mandate = _signed_mandate("obs-allow-1")
    tx = ProposedTransaction(merchant_id="merchant-a", amount=500.0, category="electronics")

    result = service.authorize(
        mandate,
        tx,
        log_path=tmp_path / "audit_log.jsonl",
        nonce_db_path=tmp_path / "nonces.db",
        approval_db_path=tmp_path / "approvals.db",
    )

    assert result.decision_id
    assert result.audit_entry["decision_id"] == result.decision_id

    last_line = (tmp_path / "audit_log.jsonl").read_text(encoding="utf-8").strip().splitlines()[-1]
    assert json.loads(last_line)["decision_id"] == result.decision_id


def test_authorize_threads_decision_id_into_the_approval_queue_row(tmp_path):
    mandate = _signed_mandate("obs-needs-human-1", max_amount=1000.0)
    tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
    approval_db_path = tmp_path / "approvals.db"

    result = service.authorize(
        mandate,
        tx,
        log_path=tmp_path / "audit_log.jsonl",
        nonce_db_path=tmp_path / "nonces.db",
        approval_db_path=approval_db_path,
    )

    assert result.request_id is not None
    queue = ApprovalQueue(approval_db_path)
    try:
        row = queue.get(result.request_id)
    finally:
        queue.close()

    assert row["decision_id"] == result.decision_id


def test_resolve_approval_mints_its_own_distinct_decision_id(tmp_path):
    """The human's decision is a separate decision event from the
    original NEEDS_HUMAN flag -- see DECISIONS.md #7 -- so it gets its
    own decision_id, not a reuse of the original one."""
    mandate = _signed_mandate("obs-resolve-1", max_amount=1000.0)
    tx = ProposedTransaction(merchant_id="merchant-a", amount=800.0, category="electronics")
    log_path = tmp_path / "audit_log.jsonl"
    approval_db_path = tmp_path / "approvals.db"

    authorize_result = service.authorize(
        mandate,
        tx,
        log_path=log_path,
        nonce_db_path=tmp_path / "nonces.db",
        approval_db_path=approval_db_path,
    )

    resolution = service.resolve_approval(
        authorize_result.request_id,
        approved=False,
        log_path=log_path,
        approval_db_path=approval_db_path,
    )

    assert resolution.decision_id
    assert resolution.decision_id != authorize_result.decision_id
    assert resolution.audit_entry["decision_id"] == resolution.decision_id
