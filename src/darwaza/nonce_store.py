"""Persistent replay/nonce store.

See DECISIONS.md: replay detection was flagged as in-memory-only — the
`seen_nonces` set lived in process memory and was lost on restart, so a
mandate could be replayed simply by restarting the process. This module
closes that gap with a SQLite-backed store that survives restarts.

As of the concurrency fixes (DECISIONS.md, Stage 3): the store's
enforcement-path operation is `claim()`, a single atomic INSERT whose
success or failure — via the PRIMARY KEY constraint and the resulting
cursor's rowcount — *is* the answer to "was this mandate_id already
spent." The old pattern (`mandate_id in store`, then, separately,
`store.add(mandate_id)`) left a window between the two calls where a
second concurrent request could read the same "not yet spent" answer —
that race is D1. `claim()` closes it by not being two calls at all.

Each thread gets its own `sqlite3.Connection` (via `threading.local`)
rather than one connection shared with `check_same_thread=False` — a
single shared connection has no way to serialize concurrent
transactions on its own and produced real `sqlite3.OperationalError` /
`DatabaseError` / `InterfaceError` (and, once, a raw interpreter-level
`SystemError`) under concurrent access (D3). WAL mode lets multiple
connections read while one writes, and `busy_timeout` makes a writer
that loses a brief lock race wait and retry instead of raising
immediately.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class NonceStore:
    """Persistent set of spent mandate ids, backed by a SQLite file.

    `claim()` is the enforcement-path primitive: atomic check-and-reserve
    in one call, used by `policy_engine.evaluate()`. `__contains__` and
    `add()` remain, but only for tests and direct inspection/tooling —
    neither is safe against a concurrent caller doing the same thing,
    because each is a single, independent statement, not the same atomic
    operation `claim()` is.
    """

    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # One tracked connection per thread that ever touches this store,
        # so close() (typically called from whichever thread constructed
        # this store, after any worker threads it handed the store to
        # have already finished) can close every connection, not just the
        # calling thread's own — see close().
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()

        # Create the schema eagerly, from a throwaway connection, so a
        # freshly constructed NonceStore is immediately usable from any
        # thread without a first-caller-creates-the-table race.
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
            "CREATE TABLE IF NOT EXISTS spent_mandates ("
            "  mandate_id TEXT PRIMARY KEY,"
            "  spent_at TEXT NOT NULL DEFAULT (datetime('now'))"
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

    def claim(self, mandate_id: str) -> bool:
        """Atomically reserve `mandate_id`. Returns True iff *this* call
        is the one that reserved it — i.e. it was not already spent by
        any earlier call, from this thread or any other. Returns False
        if it was already spent.

        This is a single INSERT; the PRIMARY KEY constraint on
        mandate_id is what makes it atomic — sqlite either inserts the
        row or raises IntegrityError, with no window between "check" and
        "act" for a second caller to land in, unlike the old
        `x in store` + `store.add(x)` pattern this replaces on the
        enforcement path (see policy_engine.evaluate()).
        """
        conn = self._connection()
        try:
            conn.execute(
                "INSERT INTO spent_mandates (mandate_id) VALUES (?)",
                (mandate_id,),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False

    def __contains__(self, mandate_id: str) -> bool:
        """Membership check, for tests and inspection only — not used on
        the enforcement path (see claim()). A `contains` check is never,
        on its own, safe against a concurrent claim landing between the
        check and whatever the caller does next."""
        row = self._connection().execute(
            "SELECT 1 FROM spent_mandates WHERE mandate_id = ?", (mandate_id,)
        ).fetchone()
        return row is not None

    def add(self, mandate_id: str) -> None:
        """Unconditionally mark `mandate_id` spent, ignoring whether it
        already was. Kept for direct test/inspection use (see
        tests/test_nonce_store.py); the enforcement path uses claim()
        instead, precisely because add() can't tell its caller whether
        *this* call was the one that claimed the id — which is the
        entire property D1's fix depends on."""
        conn = self._connection()
        conn.execute(
            "INSERT OR IGNORE INTO spent_mandates (mandate_id) VALUES (?)",
            (mandate_id,),
        )
        conn.commit()

    def close(self) -> None:
        """Close every connection this store opened, across every thread
        that used it — not just the calling thread's own. Safe to call
        once all threads sharing this store instance have finished using
        it (the usual pattern: a test or the CLI joins its worker threads
        first, then calls close() from the thread that constructed the
        store)."""
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            conn.close()
        self._local.conn = None
