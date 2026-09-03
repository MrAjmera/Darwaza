"""Unit tests for the persistent (SQLite-backed) replay/nonce store."""

from __future__ import annotations

from darwaza.nonce_store import NonceStore


def test_fresh_store_does_not_contain_unseen_id(tmp_path):
    store = NonceStore(tmp_path / "nonces.db")
    assert "never-seen" not in store


def test_add_then_contains(tmp_path):
    store = NonceStore(tmp_path / "nonces.db")
    store.add("mandate-1")
    assert "mandate-1" in store


def test_add_is_idempotent():
    # Calling add() twice on the same id must not raise — a caller
    # re-marking after a crash should be a no-op, not an error.
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        store = NonceStore(Path(d) / "nonces.db")
        store.add("mandate-1")
        store.add("mandate-1")
        assert "mandate-1" in store


def test_persists_across_separate_store_instances(tmp_path):
    # This is the actual bug being fixed: the old in-memory set() forgot
    # everything on process restart. A second NonceStore pointed at the
    # same file must see what the first one wrote.
    db_path = tmp_path / "nonces.db"

    first_run = NonceStore(db_path)
    first_run.add("replayed-mandate")
    first_run.close()

    second_run = NonceStore(db_path)  # simulates a fresh process
    assert "replayed-mandate" in second_run


def test_different_files_are_independent(tmp_path):
    store_a = NonceStore(tmp_path / "a.db")
    store_b = NonceStore(tmp_path / "b.db")
    store_a.add("only-in-a")
    assert "only-in-a" in store_a
    assert "only-in-a" not in store_b
