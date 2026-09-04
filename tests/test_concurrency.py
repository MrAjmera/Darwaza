"""Concurrency defects (D1, D2, D3) -- fixed as of Stage 3:
- D1: policy_engine.evaluate() now claims the nonce atomically, as its
  own last check (nonce_claimer.claim(), a single INSERT keyed on a
  PRIMARY KEY), instead of the caller checking membership and adding
  separately. See policy_engine.py and DECISIONS.md.
- D2: audit_log.append_entry() now wraps the whole read-tip-then-write
  sequence in an OS-level file lock (portalocker), so concurrent writers
  can no longer both read the same prev_hash and fork the chain.
- D3: nonce_store.py and approval_queue.py now give each thread its own
  sqlite3 connection (via threading.local), with WAL mode and
  busy_timeout, instead of sharing one connection across threads.

These are genuine races, not deterministic bugs -- a single green run
proves nothing. Per the reviewer's instruction, each of these was run
at least 10 times in a loop after the fix, not once, and the pass count
out of however many runs is reported in the Stage 3 commit/report, not
just "passed." Do not weaken these assertions to make them pass -- if
they fail, the code is wrong, not the test.
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
    return m.model_copy(update={"signature": keys.sign(m.principal_id, m.signing_payload())})


def test_D1_replay_protection_allows_exactly_one_under_concurrency(tmp_path):
    """8 concurrent requests against the SAME single-use mandate must
    produce exactly one ALLOW. evaluate() now claims the nonce itself,
    atomically, as its last check -- no external store.add() call is
    involved on the enforcement path any more (see policy_engine.py)."""
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
