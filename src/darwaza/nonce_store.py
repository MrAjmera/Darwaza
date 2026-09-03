"""Persistent replay/nonce store.

See DECISIONS.md: replay detection was flagged as in-memory-only — the
`seen_nonces` set lived in process memory and was lost on restart, so a
mandate could be replayed simply by restarting the process. This module
closes that gap with a SQLite-backed store that survives restarts.

`NonceStore` is deliberately NOT a general-purpose cache or queue — one
table, two operations — because those two operations
(`__contains__`, `add`) are exactly what `policy_engine.evaluate()`
already expects from `seen_nonces`. That means `evaluate()` itself needs
no changes: it stays a pure function that takes whatever object supports
`x in seen_nonces`, and the caller (the CLI, here) decides whether that
object is an in-memory set (fine for tests) or this persistent store
(what a real deployment needs).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class NonceStore:
    """Persistent set of spent mandate ids, backed by a SQLite file.

    A mandate_id is "spent" once `add()` has been called on it — the
    caller is responsible for only calling `add()` after a successful
    ALLOW, same contract the in-memory set had. `__contains__` lets this
    stand in anywhere `mandate_id in seen_nonces` is used.
    """

    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: this CLI is single-process/single-run,
        # but the flag keeps the store usable from a test fixture or a
        # future web server without surprising sqlite thread errors.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS spent_mandates ("
            "  mandate_id TEXT PRIMARY KEY,"
            "  spent_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
        self._conn.commit()

    def __contains__(self, mandate_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM spent_mandates WHERE mandate_id = ?", (mandate_id,)
        ).fetchone()
        return row is not None

    def add(self, mandate_id: str) -> None:
        # INSERT OR IGNORE: calling add() twice on the same id (e.g. a
        # caller re-marking after a crash) must not raise — the mandate
        # was already spent, which is exactly the state we want.
        self._conn.execute(
            "INSERT OR IGNORE INTO spent_mandates (mandate_id) VALUES (?)",
            (mandate_id,),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
