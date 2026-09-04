"""Unit tests for rate_limit.py's TokenBucket and RateLimiter.

A fake, manually-advanced clock is used throughout instead of real
time.sleep() calls -- deterministic and fast, and it's the refill *rate*
being tested, not wall-clock behavior.
"""

from __future__ import annotations

import threading

import pytest

from darwaza.rate_limit import RateLimiter, TokenBucket


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def test_bucket_allows_up_to_capacity_bursts():
    clock = FakeClock()
    bucket = TokenBucket(capacity=3, refill_rate_per_second=1, clock=clock)

    assert bucket.try_consume() is True
    assert bucket.try_consume() is True
    assert bucket.try_consume() is True
    assert bucket.try_consume() is False  # burst exhausted, no time has passed


def test_bucket_refills_over_time():
    clock = FakeClock()
    bucket = TokenBucket(capacity=1, refill_rate_per_second=1, clock=clock)

    assert bucket.try_consume() is True
    assert bucket.try_consume() is False  # empty

    clock.advance(1.0)  # one full token's worth of time
    assert bucket.try_consume() is True


def test_bucket_refill_never_exceeds_capacity():
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_rate_per_second=1, clock=clock)

    clock.advance(100.0)  # way more than enough to overfill if unclamped
    assert bucket.try_consume() is True
    assert bucket.try_consume() is True
    assert bucket.try_consume() is False


def test_bucket_retry_after_seconds_is_zero_when_available():
    clock = FakeClock()
    bucket = TokenBucket(capacity=1, refill_rate_per_second=1, clock=clock)
    assert bucket.retry_after_seconds() == 0.0


def test_bucket_retry_after_seconds_is_positive_when_exhausted():
    clock = FakeClock()
    bucket = TokenBucket(capacity=1, refill_rate_per_second=0.5, clock=clock)
    assert bucket.try_consume() is True

    retry_after = bucket.retry_after_seconds()
    assert retry_after == pytest.approx(2.0)  # need 1 token at 0.5/sec


def test_bucket_constructor_rejects_non_positive_values():
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_rate_per_second=1)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_rate_per_second=0)


def test_bucket_try_consume_is_atomic_under_concurrency():
    """The exact D1-shaped bug this module must not repeat: N threads
    racing try_consume() against a bucket with capacity 1 must produce
    exactly 1 success, not "check then decrement" letting several
    through. clock=time.monotonic (real time) here specifically so this
    is a genuine concurrency test, not just sequential calls against a
    fake clock."""
    import time

    bucket = TokenBucket(capacity=1, refill_rate_per_second=0.0001, clock=time.monotonic)
    barrier = threading.Barrier(20)
    successes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        if bucket.try_consume():
            with lock:
                successes.append(1)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1


# ---------------------------------------------------------------------------
# RateLimiter: keyed per (agent, mandate)
# ---------------------------------------------------------------------------


def test_rate_limiter_keys_independently_per_mandate_for_the_same_agent():
    clock = FakeClock()
    limiter = RateLimiter(capacity=1, refill_rate_per_second=1, clock=clock)

    allowed_a, _ = limiter.allow("agent-1", "mandate-a")
    allowed_b, _ = limiter.allow("agent-1", "mandate-b")

    assert allowed_a is True
    assert allowed_b is True  # different mandate, same agent -- independent budget


def test_rate_limiter_keys_independently_per_agent_for_the_same_mandate():
    clock = FakeClock()
    limiter = RateLimiter(capacity=1, refill_rate_per_second=1, clock=clock)

    allowed_a, _ = limiter.allow("agent-1", "mandate-x")
    allowed_b, _ = limiter.allow("agent-2", "mandate-x")

    assert allowed_a is True
    assert allowed_b is True  # different agent, same mandate -- independent budget


def test_rate_limiter_throttles_repeated_requests_for_the_same_pair():
    clock = FakeClock()
    limiter = RateLimiter(capacity=2, refill_rate_per_second=1, clock=clock)

    assert limiter.allow("agent-1", "mandate-a")[0] is True
    assert limiter.allow("agent-1", "mandate-a")[0] is True
    allowed, retry_after = limiter.allow("agent-1", "mandate-a")
    assert allowed is False
    assert retry_after > 0


def test_rate_limiter_a_looping_agent_gets_throttled_after_burst():
    """The scenario the whole module exists for: a runaway agent
    resubmitting the same mandate far faster than any human would."""
    clock = FakeClock()
    limiter = RateLimiter(capacity=5, refill_rate_per_second=1 / 60, clock=clock)

    outcomes = [limiter.allow("looping-agent", "mandate-victim")[0] for _ in range(20)]

    assert outcomes.count(True) == 5  # only the burst capacity gets through
    assert outcomes.count(False) == 15
