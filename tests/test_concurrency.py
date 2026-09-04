"""Concurrency defects (D1, D2, D3), reproduced against the current code.

These tests are expected to FAIL until Stage 3 fixes the underlying races:
- D1: policy_engine.evaluate() checks `mandate_id in seen_nonces` and the
  caller adds it afterward -- a classic check-then-act TOCTOU gap.
- D2: audit_log.append_entry() reads the last line for prev_hash, then
  writes -- concurrent writers can read the same prev_hash and both chain
  off it, forking the log.
- D3: nonce_store.py and approval_queue.py each share one sqlite3
  connection across threads with no WAL mode and no busy_timeout.

Do not weaken these assertions to make them pass -- if they fail, the
code is wrong, not the test.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from darwaza import keys
from darwaza.approval_queue import ApprovalQueue
from darwaza.audit_log import append_entry, verify_chain
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)


def _signed_single_use_mandate(mandate_id: str) -> NormalizedMandate:
    m = NormalizedMandate(
        mandate_id=mandate_id,
        principal_id="p1",
        expiry=FUTURE,
        signature="placeholder",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    return m.model_copy(update={"signature": keys.sign(m.signing_payload())})


def test_D1_replay_protection_allows_exactly_one_under_concurrency(tmp_path):
    """8 concurrent requests against the SAME single-use mandate must
    produce exactly one ALLOW. Today, every request in flight between
    evaluate()'s membership check and the caller's store.add() call passes
    the check, so this reliably allows more than one."""
    store = NonceStore(tmp_path / "nonces.db")
    mandate = _signed_single_use_mandate("replay-race-1")
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    barrier = threading.Barrier(8)
    allows: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        decision = evaluate(mandate, tx, store)
        if decision.outcome == Outcome.ALLOW:
            store.add(mandate.mandate_id)
            with lock:
                allows.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    store.close()

    assert len(allows) == 1, (
        f"expected exactly 1 ALLOW for a single-use mandate under 8 "
        f"concurrent requests, got {len(allows)} -- replay protection is "
        f"not atomic (check-then-add TOCTOU)"
    )


def test_D2_audit_chain_does_not_fork_under_concurrent_appends(tmp_path):
    """10 concurrent append_entry() calls, nobody tampering -- the chain
    must still verify and no entry may be lost. append_entry() currently
    reads the last line for prev_hash, then writes; concurrent writers can
    read the same prev_hash and both chain off it."""
    log_path = tmp_path / "audit_log.jsonl"

    def worker(i: int) -> None:
        append_entry(
            log_path,
            f"mandate-{i}",
            Decision(outcome=Outcome.ALLOW, reason="ok", failed_check=None),
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok, reason = verify_chain(log_path)
    assert ok, f"chain should be intact after 10 concurrent non-tampering writers: {reason}"

    lines = [l for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 10, f"expected 10 entries, found {len(lines)} -- a write was lost"


def test_D3_nonce_store_survives_concurrent_access_without_sqlite_errors(tmp_path):
    """Concurrent add()/__contains__ calls against one NonceStore must not
    raise a sqlite3 error. The store shares one connection
    (check_same_thread=False) with no WAL mode and no busy_timeout, so
    concurrent writers collide -- in practice this surfaces as
    sqlite3.OperationalError ("cannot start/commit a transaction..."),
    but also as sqlite3.DatabaseError/InterfaceError depending on timing,
    so this catches sqlite3.Error broadly rather than one specific
    subclass."""
    store = NonceStore(tmp_path / "nonces.db")
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            store.add(f"mandate-{i}")
            _ = f"mandate-{i}" in store
        except sqlite3.Error as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    store.close()

    assert not errors, f"concurrent NonceStore access raised: {errors}"


def test_D3_approval_queue_survives_concurrent_enqueue_without_sqlite_errors(tmp_path):
    """Same defect as above, in approval_queue.py's shared connection."""
    queue = ApprovalQueue(tmp_path / "approvals.db")
    mandate = _signed_single_use_mandate("aq-race")
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)
    decision = Decision(
        outcome=Outcome.NEEDS_HUMAN, reason="test", failed_check="human_review_threshold"
    )

    errors: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            queue.enqueue(mandate, tx, decision, "explanation")
        except sqlite3.Error as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    queue.close()

    assert not errors, f"concurrent ApprovalQueue access raised: {errors}"
