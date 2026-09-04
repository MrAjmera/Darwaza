"""Structured logging, decision timing, and in-process counters.

This is deliberately NOT the audit log. `audit_log.py` is a security
artifact: append-only, hash-chained, meant to reconstruct a dispute
months later, with retention driven by compliance/legal needs. What's
in this module is operational observability: meant for a dashboard or
an on-call engineer right now, safe to sample, safe to drop, safe to
lose on restart. Conflating the two would mean either the audit log
grows operational noise it doesn't need to keep forever, or
observability inherits the audit log's durability guarantees it
doesn't need to pay for. They have different consumers and different
retention, so they stay two different modules with two different
storage strategies (an append-only file with a real durability contract
vs. in-memory counters that reset on restart).

What this module provides:
- `new_decision_id()` — mint a UUID at the door (service.authorize() /
  service.resolve_approval()) and thread the SAME id through every
  structured log line for that decision, the audit entry, and (for
  NEEDS_HUMAN) the approval queue row — so a human debugging one
  request can find every trace of it by one id, across three different
  storage locations with three different purposes.
- `log_decision(...)` / `log_resolution(...)` — one structured JSON log
  line per decision, via the standard `logging` module (so it composes
  with whatever log aggregation a real deployment already has) rather
  than a bespoke file format.
- `time_decision(...)` — a context manager that measures wall-clock
  time for a block of code, used to separately time the one check with
  real computational cost (Ed25519 signature verification) from the
  rest of evaluate()'s checks (plain field comparisons, each on the
  order of nanoseconds). See the note on `time_decision` for why this
  module does not attempt to time each of evaluate()'s ~8 checks
  individually.
- `COUNTERS` — a thread-safe, in-process, ALLOW/DENY/NEEDS_HUMAN
  counter broken down by `failed_check`. Process-lifetime only: this is
  what api.py's `/metrics` reports, and it resets on restart, same as
  any other in-memory metric would in a real deployment. It is NOT a
  substitute for the audit log's durable, complete history — see
  api.py's `/metrics` docstring for exactly what it does and doesn't
  claim.

Why per-check timing is "signature verification, timed separately, plus
total decision time" rather than eight individually-timed checks:
`policy_engine.evaluate()` is one function that returns on the first
failing check, by design (DECISIONS.md's ordering rationale). Splitting
it into eight separately-callable, separately-timable functions purely
so this module could instrument each one would mean refactoring the
one function this project has been most deliberate about keeping
simple, linear, and auditable (DECISIONS.md #2) — for a payoff that
doesn't exist, because every check except signature verification is a
plain comparison against already-loaded fields, each too fast to
produce a meaningful timing signal on its own. Signature verification
(real Ed25519 crypto) is the one check with a cost worth actually
measuring, so it's measured on its own; everything else is accounted
for in the total.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Iterator

_logger = logging.getLogger("darwaza")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    # propagate stays True (the default): letting records also reach the
    # root logger is what lets pytest's caplog fixture see them in tests
    # (tests/test_observability.py), and in production it's harmless
    # (nothing else in this app configures a root handler that would
    # double-print).


def new_decision_id() -> str:
    """Mint a fresh id for one decision event -- one call to
    service.authorize() or service.resolve_approval(). Threaded through
    every structured log line for that event, the audit log entry
    (audit_log.append_entry()'s `decision_id` field), and — for
    NEEDS_HUMAN — the approval queue row (approval_queue.enqueue()'s
    `decision_id` column)."""
    return str(uuid.uuid4())


def _log(event: str, **fields) -> None:
    """One structured JSON line per event. Uses the standard `logging`
    module (not print()) so this composes with whatever log handling a
    real deployment already has (log levels, shipping to a collector,
    etc.) rather than a bespoke mechanism only this project understands."""
    record = {"event": event, "timestamp": time.time(), **fields}
    _logger.info(json.dumps(record, sort_keys=True, default=str))


@contextmanager
def time_decision() -> Iterator[dict]:
    """Context manager yielding a dict that gets a `duration_ms` key
    filled in once the block exits. Usage:

        timing = {}
        with time_decision() as t:
            ...
        # t["duration_ms"] is now set

    A plain dict rather than a return value because context managers
    can't hand back a value computed only at __exit__ time any other
    way without a small wrapper object — this is the wrapper object,
    minimal as possible.
    """
    result: dict = {}
    start = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - start) * 1000.0


def log_decision(
    *,
    decision_id: str,
    mandate_id: str,
    outcome: str,
    failed_check: str | None,
    evaluate_duration_ms: float,
    signature_verify_duration_ms: float | None,
    request_id: str | None = None,
) -> None:
    """One structured log line for an authorize() call. Called after
    evaluate() has already run — this never influences the decision,
    same spirit as llm_explainer.explain() being strictly downstream of
    ALLOW/DENY/NEEDS_HUMAN (DECISIONS.md #6), just for logging instead
    of explaining."""
    _log(
        "decision",
        decision_id=decision_id,
        mandate_id=mandate_id,
        outcome=outcome,
        failed_check=failed_check,
        evaluate_duration_ms=round(evaluate_duration_ms, 4),
        signature_verify_duration_ms=(
            round(signature_verify_duration_ms, 4)
            if signature_verify_duration_ms is not None
            else None
        ),
        request_id=request_id,
    )
    COUNTERS.record(outcome, failed_check)


def log_resolution(
    *,
    decision_id: str,
    request_id: str,
    mandate_id: str,
    outcome: str,
    approved: bool,
    razorpay_order_id: str | None,
    razorpay_error: str | None,
) -> None:
    """One structured log line for a resolve_approval() call (a human's
    approve/deny). A distinct event type from `decision` — this is a
    human's decision, recorded with its own fresh decision_id (see
    service.resolve_approval()), correlated back to the original request
    via `request_id`/`mandate_id`, not treated as the same event."""
    _log(
        "resolution",
        decision_id=decision_id,
        request_id=request_id,
        mandate_id=mandate_id,
        outcome=outcome,
        approved=approved,
        razorpay_order_id=razorpay_order_id,
        razorpay_error=razorpay_error,
    )
    COUNTERS.record(outcome, None if approved else "human_review_denied")


class Counters:
    """Thread-safe, in-process counts of every decision this process has
    recorded, broken down by (outcome, failed_check). Process-lifetime
    only -- see module docstring for why this is not, and is not meant
    to be, the audit log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[tuple[str, str | None], int] = {}

    def record(self, outcome: str, failed_check: str | None) -> None:
        with self._lock:
            key = (outcome, failed_check)
            self._counts[key] = self._counts.get(key, 0) + 1

    def snapshot(self) -> dict:
        """Returns {"by_outcome": {...}, "by_failed_check": {...}} --
        by_outcome always has ALLOW/DENY/NEEDS_HUMAN keys (zero-filled
        if never seen); by_failed_check only has keys that have actually
        occurred."""
        with self._lock:
            items = list(self._counts.items())
        by_outcome = {"ALLOW": 0, "DENY": 0, "NEEDS_HUMAN": 0}
        by_failed_check: dict[str, int] = {}
        for (outcome, failed_check), count in items:
            by_outcome[outcome] = by_outcome.get(outcome, 0) + count
            if failed_check:
                by_failed_check[failed_check] = by_failed_check.get(failed_check, 0) + count
        return {"by_outcome": by_outcome, "by_failed_check": by_failed_check}

    def reset(self) -> None:
        """Test-only: clear all counts. Nothing in production code calls
        this -- counters are meant to accumulate for the process's
        lifetime."""
        with self._lock:
            self._counts.clear()


COUNTERS = Counters()
