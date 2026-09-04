"""Shared test doubles. Not itself a test module (no test_ prefix) --
pytest won't collect it, but test files in this directory can import it
directly since pytest's default rootdir-relative import inserts this
directory onto sys.path.
"""

from __future__ import annotations


class FakeNonceClaimer:
    """Minimal in-memory stand-in for nonce_store.NonceStore's claim()
    contract (policy_engine.NonceClaimer), for unit tests that don't need
    real persistence -- just the same atomic claim-once semantics
    evaluate() depends on since Stage 3. Single-threaded (test) use only;
    no locking, because nothing in a synchronous unit test needs it.
    """

    def __init__(self, already_claimed=()) -> None:
        self._claimed = set(already_claimed)

    def claim(self, mandate_id: str) -> bool:
        if mandate_id in self._claimed:
            return False
        self._claimed.add(mandate_id)
        return True

    def __contains__(self, mandate_id: str) -> bool:
        return mandate_id in self._claimed
