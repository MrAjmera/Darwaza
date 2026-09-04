"""Token-bucket rate limiting, keyed per-agent and per-mandate — NOT
per-IP. See DECISIONS.md's Stage 5 entry for the full rationale; in
short: a human makes a handful of purchases an hour, a looping agent
can make thousands in the same window, so throttling here is an
authorization control (stopping a class of attack the gate otherwise
doesn't) rather than infrastructure hygiene (protecting the process
from being overwhelmed). Per-IP wouldn't fit that job — a legitimate
agent platform can run many agents behind one IP, and an attacker
controlling many IPs defeats a per-IP limit trivially; what matters is
*which agent, spending which mandate*, not where the packet came from.

Only wired into api.py's `POST /v1/authorize` (see there) — the CLI's
`decide`/`simulate`/`approve`/`deny` are human-invoked, one at a time,
never the automated tight loop this exists to catch.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket: `capacity` tokens available at once (a
    burst allowance), refilling continuously at `refill_rate_per_second`.
    `try_consume()` is the only mutating operation — refill is computed
    lazily from elapsed wall-clock time on each call, not by a
    background thread, so an idle bucket costs nothing between calls.

    Internally locked: `try_consume()` does its own check-and-decrement
    under one lock, not a separate check then a separate decrement — the
    same reason nonce_store.NonceStore.claim() is one atomic operation
    rather than "check membership, then add" (see DECISIONS.md's Stage 3
    entries on D1). Two threads racing `try_consume()` on the same
    bucket must not both be able to read "tokens available" before
    either decrements.
    """

    def __init__(self, capacity: float, refill_rate_per_second: float, *, clock=time.monotonic) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_rate_per_second <= 0:
            raise ValueError("refill_rate_per_second must be positive")
        self._capacity = capacity
        self._refill_rate = refill_rate_per_second
        self._clock = clock
        self._tokens = capacity
        self._last_refill = clock()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last_refill)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

    def try_consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def retry_after_seconds(self, tokens: float = 1.0) -> float:
        """How long until `tokens` would be available, given the current
        fill level. 0.0 if already available."""
        with self._lock:
            self._refill_locked()
            deficit = tokens - self._tokens
            if deficit <= 0:
                return 0.0
            return deficit / self._refill_rate


class RateLimiter:
    """One TokenBucket per (agent_key, mandate_id) pair, created lazily
    on first use. `agent_key` is the caller's choice of identity — see
    api.py's `authorize()`, which uses `mandate.agent_id or
    mandate.principal_id` (an AP2 mandate names an acting agent
    separately from the principal; an ACP token or an AP2 mandate with
    no distinct agent falls back to the principal who authorized it —
    every mandate has at least one of these).

    Keying on the *pair*, not just the agent, matters: a legitimate
    agent acting correctly under several different mandates for the
    same principal shouldn't have one mandate's usage count against
    another's budget. Keying on the *mandate alone* would matter less
    here since D1/D4 already make most mandates single-use or
    quickly-exhausted by the policy engine itself — the agent dimension
    is what actually catches a *loop*, which by definition keeps
    resubmitting even after the first attempt already got a decision.
    """

    def __init__(self, capacity: float, refill_rate_per_second: float, *, clock=time.monotonic) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate_per_second
        self._clock = clock
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def _bucket_for(self, agent_key: str, mandate_id: str) -> TokenBucket:
        key = (agent_key, mandate_id)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self._capacity, self._refill_rate, clock=self._clock)
                self._buckets[key] = bucket
            return bucket

    def allow(self, agent_key: str, mandate_id: str) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds). retry_after_seconds
        is always 0.0 when allowed is True."""
        bucket = self._bucket_for(agent_key, mandate_id)
        if bucket.try_consume():
            return True, 0.0
        return False, bucket.retry_after_seconds()
