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
            "  status TEXT NOT NULL DEFAULT 'pending',"  # pending|approved|denied
            "  created_at TEXT NOT NULL,"
            "  resolved_at TEXT,"
            "  resolved_by TEXT"
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
    ) -> str:
        request_id = str(uuid.uuid4())
        conn = self._connection()
        conn.execute(
            "INSERT INTO pending_approvals "
            "(id, mandate_id, mandate_json, proposed_tx_json, reason, explanation, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
            (
                request_id,
                mandate.mandate_id,
                mandate.model_dump_json(),
                proposed_tx.model_dump_json(),
                decision.reason,
                explanation,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return request_id

    def list_pending(self) -> list[dict]:
        rows = self._connection().execute(
            "SELECT id, mandate_id, reason, explanation, created_at "
            "FROM pending_approvals WHERE status = 'pending' ORDER BY created_at"
        ).fetchall()
        return [
            {"id": r[0], "mandate_id": r[1], "reason": r[2], "explanation": r[3], "created_at": r[4]}
            for r in rows
        ]

    def get(self, request_id: str) -> dict | None:
        row = self._connection().execute(
            "SELECT id, mandate_id, mandate_json, proposed_tx_json, reason, explanation, status "
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
        }

    def resolve(self, request_id: str, *, approved: bool, resolved_by: str = "human") -> None:
        status = "approved" if approved else "denied"
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

    def close(self) -> None:
        """Close every connection this queue opened, across every thread
        that used it — see nonce_store.NonceStore.close(), same pattern
        and same reasoning."""
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            conn.close()
        self._local.conn = None
