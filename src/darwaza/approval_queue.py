"""Persistent human-approval queue for NEEDS_HUMAN decisions.

`policy_engine.evaluate()` decides NEEDS_HUMAN deterministically
(DECISIONS.md #5). This module is what happens next: the request waits
here until a real person approves or denies it. That approve/deny action
is the thing the project's thesis is actually about — "when a human
buys, liability is anchored by a human action; when an agent buys, that
anchor disappears." A NEEDS_HUMAN request that gets a real human
decision restores exactly that anchor for one transaction, instead of
leaving accountability undefined.

Backed by SQLite for the same reason nonce_store.py is: a pending
request must survive a process restart, and a single file needs no
service to run. Same explicitly-named limit as nonce_store.py: this is
one file for one instance, not a multi-instance-safe queue.

Concurrency (Stage 3, see DECISIONS.md and nonce_store.py's module
docstring for the same fix in more detail): each thread gets its own
`sqlite3.Connection` via `threading.local`, instead of one connection
shared with `check_same_thread=False` — sharing produced real
`sqlite3.OperationalError`/`InterfaceError` under concurrent access
(D3). WAL mode plus `busy_timeout` let concurrent connections coexist
without the caller needing to retry manually.

Stage 6: `status` used to go straight from 'pending' to a terminal
'approved' the moment a human clicked approve — before
razorpay_client.create_order() ever ran. A process that died in that gap
left a row saying 'approved' with no way to tell, from the queue alone,
whether the Razorpay order behind it actually got created (see
tests/test_defect_hunt.py's `test_approved_status_does_not_distinguish_
execution_from_a_crash`, which proves exactly this). 'approved' is no
longer a status this module ever sets: a human's approval now produces
'approved_pending_execution', and only a *successful* Razorpay call
(via mark_executed()) advances it to the real terminal state,
'executed'. A failed attempt (record_execution_failure()) leaves it in
'approved_pending_execution' — retryable, not lost — rather than
inventing a dead-end 'execution_failed' status: the human already said
yes, so the system's job is to keep the request visible and retryable
until it actually reaches Razorpay, not to give up on it.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from darwaza.schema import Decision, NormalizedMandate, ProposedTransaction


class ApprovalQueue:
    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Tracked across every thread that touches this store, so
        # close() can close every connection it opened, not just the
        # calling thread's own — see close().
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()

        # Create the schema eagerly, from a throwaway connection, so a
        # freshly constructed ApprovalQueue is immediately usable from
        # any thread without a first-caller-creates-the-table race.
        conn = self._open_connection()
        conn.close()

    def _open_connection(self) -> sqlite3.Connection:
        # check_same_thread=False here is not the original bug: D3 came
        # from many threads sharing and operating on ONE connection
        # concurrently, which interleaved that connection's implicit
        # transaction state. Here every thread gets its OWN connection
        # (see _connection()) and only that thread ever executes against
        # it. The flag's only effect is letting close() (see below) do a
        # purely sequential cleanup pass from a different, coordinating
        # thread after the owning thread is done with it — never
        # concurrent access to the same connection from two threads.
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_approvals ("
            "  id TEXT PRIMARY KEY,"
            "  mandate_id TEXT NOT NULL,"
            "  mandate_json TEXT NOT NULL,"
            "  proposed_tx_json TEXT NOT NULL,"
            "  reason TEXT NOT NULL,"
            "  explanation TEXT NOT NULL,"
            # pending -> approved_pending_execution -> executed
            #         -> denied (terminal)
            # See module docstring, Stage 6, for why 'approved' alone is
            # no longer a status this module ever sets.
            "  status TEXT NOT NULL DEFAULT 'pending',"
            "  created_at TEXT NOT NULL,"
            "  resolved_at TEXT,"
            "  resolved_by TEXT,"
            "  decision_id TEXT,"  # Stage 5, see observability.py -- nullable,
                                    # same reasoning as audit_log.py's decision_id.
            "  razorpay_order_id TEXT,"  # Stage 6 -- set only by mark_executed().
            "  execution_attempts INTEGER NOT NULL DEFAULT 0,"  # Stage 6
            "  last_execution_error TEXT,"  # Stage 6 -- most recent failure, if any.
            "  executed_at TEXT"  # Stage 6
            ")"
        )
        conn.commit()
        return conn

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open_connection()
            self._local.conn = conn
            with self._connections_lock:
                self._connections.append(conn)
        return conn

    def enqueue(
        self,
        mandate: NormalizedMandate,
        proposed_tx: ProposedTransaction,
        decision: Decision,
        explanation: str,
        *,
        decision_id: str | None = None,
    ) -> str:
        request_id = str(uuid.uuid4())
        conn = self._connection()
        conn.execute(
            "INSERT INTO pending_approvals "
            "(id, mandate_id, mandate_json, proposed_tx_json, reason, explanation, status, created_at, decision_id) "
            "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                request_id,
                mandate.mandate_id,
                mandate.model_dump_json(),
                proposed_tx.model_dump_json(),
                decision.reason,
                explanation,
                datetime.now(timezone.utc).isoformat(),
                decision_id,
            ),
        )
        conn.commit()
        return request_id

    def list_pending(self) -> list[dict]:
        rows = self._connection().execute(
            "SELECT id, mandate_id, reason, explanation, created_at, decision_id "
            "FROM pending_approvals WHERE status = 'pending' ORDER BY created_at"
        ).fetchall()
        return [
            {
                "id": r[0],
                "mandate_id": r[1],
                "reason": r[2],
                "explanation": r[3],
                "created_at": r[4],
                "decision_id": r[5],
            }
            for r in rows
        ]

    def get(self, request_id: str) -> dict | None:
        row = self._connection().execute(
            "SELECT id, mandate_id, mandate_json, proposed_tx_json, reason, explanation, status, "
            "decision_id, razorpay_order_id, execution_attempts, last_execution_error "
            "FROM pending_approvals WHERE id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "mandate_id": row[1],
            "mandate_json": row[2],
            "proposed_tx_json": row[3],
            "reason": row[4],
            "explanation": row[5],
            "status": row[6],
            "decision_id": row[7],
            "razorpay_order_id": row[8],
            "execution_attempts": row[9],
            "last_execution_error": row[10],
        }

    def resolve(self, request_id: str, *, approved: bool, resolved_by: str = "human") -> None:
        """Record a human's approve/deny decision. Approval no longer
        lands on a terminal status here — see the module docstring
        (Stage 6) for why 'approved_pending_execution' exists instead of
        'approved': execution against Razorpay hasn't happened yet, and
        this call alone must not claim that it has. Only mark_executed()
        (below) ever sets 'executed'."""
        status = "approved_pending_execution" if approved else "denied"
        conn = self._connection()
        cur = conn.execute(
            "UPDATE pending_approvals SET status = ?, resolved_at = ?, resolved_by = ? "
            "WHERE id = ? AND status = 'pending'",
            (status, datetime.now(timezone.utc).isoformat(), resolved_by, request_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError(
                f"No *pending* approval with id '{request_id}' "
                "(already resolved, or the id doesn't exist)."
            )

    def mark_executed(self, request_id: str, *, razorpay_order_id: str) -> None:
        """Advance a request from 'approved_pending_execution' to the
        real terminal state, 'executed' — called only once
        razorpay_client.create_order() has actually returned an order (a
        genuinely new one, or an existing one found via its own
        idempotency-by-receipt lookup — either way, a definite,
        already-confirmed result). Guarded to the same 'only from this
        exact prior status' pattern as resolve(): a row that's already
        'executed', or that's still 'pending'/'denied', can't be marked
        executed out from under itself, which matters because this is
        exactly the operation service.execute_approval() may call
        multiple times if a retry raced with an earlier attempt's
        success."""
        conn = self._connection()
        cur = conn.execute(
            "UPDATE pending_approvals SET status = 'executed', razorpay_order_id = ?, executed_at = ? "
            "WHERE id = ? AND status = 'approved_pending_execution'",
            (razorpay_order_id, datetime.now(timezone.utc).isoformat(), request_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError(
                f"No request '{request_id}' in 'approved_pending_execution' state "
                "(already executed, still pending human review, or denied)."
            )

    def record_execution_failure(self, request_id: str, *, error: str) -> None:
        """Record a failed (or exhausted-retries) execution attempt
        *without* changing status — the request stays
        'approved_pending_execution' (see module docstring: execution is
        retryable by design, there is no dead-end 'failed' status) but
        the queue remembers how many attempts have been made and what
        the last error was, so `review`/`GET /v1/approvals/pending-
        execution` output can tell a fresh, never-attempted approval
        apart from one that's already failed N times."""
        conn = self._connection()
        conn.execute(
            "UPDATE pending_approvals SET execution_attempts = execution_attempts + 1, "
            "last_execution_error = ? WHERE id = ? AND status = 'approved_pending_execution'",
            (error, request_id),
        )
        conn.commit()

    def list_pending_execution(self) -> list[dict]:
        """Requests a human already approved that haven't successfully
        reached Razorpay yet — never attempted, or attempted and failed.
        This is what makes the 'approved, not yet executed' state
        visible and actionable (the gap test_defect_hunt.py's crash
        scenario proved was previously invisible) instead of silently
        stuck forever."""
        rows = self._connection().execute(
            "SELECT id, mandate_id, reason, created_at, decision_id, execution_attempts, "
            "last_execution_error FROM pending_approvals "
            "WHERE status = 'approved_pending_execution' ORDER BY created_at"
        ).fetchall()
        return [
            {
                "id": r[0],
                "mandate_id": r[1],
                "reason": r[2],
                "created_at": r[3],
                "decision_id": r[4],
                "execution_attempts": r[5],
                "last_execution_error": r[6],
            }
            for r in rows
        ]

    def close(self) -> None:
        """Close every connection this queue opened, across every thread
        that used it — see nonce_store.NonceStore.close(), same pattern
        and same reasoning."""
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            conn.close()
        self._local.conn = None
