"""Unit tests for the persistent (SQLite-backed) replay/nonce store.

Every store opened in these tests is explicitly closed before the test
ends. This matters on Windows specifically: an open sqlite3 connection
holds the underlying file open, and pytest's `tmp_path` fixture tries to
delete that directory during teardown — on Windows (unlike POSIX) you
cannot delete a file that's still open, so an unclosed NonceStore turns
into a PermissionError at teardown, not at the point of the actual bug.
"""

from __future__ import annotations

from darwaza.nonce_store import NonceStore


def test_fresh_store_does_not_contain_unseen_id(tmp_path):
    store = NonceStore(tmp_path / "nonces.db")
    try:
        assert "never-seen" not in store
    finally:
        store.close()


def test_add_then_contains(tmp_path):
    store = NonceStore(tmp_path / "nonces.db")
    try:
        store.add("mandate-1")
        assert "mandate-1" in store
    finally:
        store.close()


def test_add_is_idempotent(tmp_path):
    # Calling add() twice on the same id must not raise — a caller
    # re-marking after a crash should be a no-op, not an error.
    store = NonceStore(tmp_path / "nonces.db")
    try:
        store.add("mandate-1")
        store.add("mandate-1")
        assert "mandate-1" in store
    finally:
        store.close()


def test_persists_across_separate_store_instances(tmp_path):
    # This is the actual bug being fixed: the old in-memory set() forgot
    # everything on process restart. A second NonceStore pointed at the
    # same file must see what the first one wrote.
    db_path = tmp_path / "nonces.db"

    first_run = NonceStore(db_path)
    first_run.add("replayed-mandate")
    first_run.close()

    second_run = NonceStore(db_path)  # simulates a fresh process
    try:
        assert "replayed-mandate" in second_run
    finally:
        second_run.close()


def test_different_files_are_independent(tmp_path):
    store_a = NonceStore(tmp_path / "a.db")
    store_b = NonceStore(tmp_path / "b.db")
    try:
        store_a.add("only-in-a")
        assert "only-in-a" in store_a
        assert "only-in-a" not in store_b
    finally:
        store_a.close()
        store_b.close()
