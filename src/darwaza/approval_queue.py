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
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from darwaza.schema import Decision, NormalizedMandate, ProposedTransaction


class ApprovalQueue:
    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
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
        self._conn.commit()

    def enqueue(
        self,
        mandate: NormalizedMandate,
        proposed_tx: ProposedTransaction,
        decision: Decision,
        explanation: str,
    ) -> str:
        request_id = str(uuid.uuid4())
        self._conn.execute(
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
        self._conn.commit()
        return request_id

    def list_pending(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, mandate_id, reason, explanation, created_at "
            "FROM pending_approvals WHERE status = 'pending' ORDER BY created_at"
        ).fetchall()
        return [
            {"id": r[0], "mandate_id": r[1], "reason": r[2], "explanation": r[3], "created_at": r[4]}
            for r in rows
        ]

    def get(self, request_id: str) -> dict | None:
        row = self._conn.execute(
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
        cur = self._conn.execute(
            "UPDATE pending_approvals SET status = ?, resolved_at = ?, resolved_by = ? "
            "WHERE id = ? AND status = 'pending'",
            (status, datetime.now(timezone.utc).isoformat(), resolved_by, request_id),
        )
        self._conn.commit()
        if cur.rowcount == 0:
            raise ValueError(
                f"No *pending* approval with id '{request_id}' "
                "(already resolved, or the id doesn't exist)."
            )

    def close(self) -> None:
        self._conn.close()
