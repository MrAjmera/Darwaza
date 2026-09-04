"""One Razorpay test-mode order, created after a human-approved
NEEDS_HUMAN request (or a deterministic ALLOW). See DECISIONS.md #7 for
what this honestly does and does not prove, and DECISIONS.md's Stage 6
entry for the retry/timeout/idempotency behavior added here.

Requires RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET (test-mode keys from
the Razorpay dashboard: Settings -> API Keys), read from config.py. If
they aren't set, create_order() raises immediately rather than
pretending to succeed — a demo step that silently no-ops on a missing
key is worse than one that fails loudly and says why. If RAZORPAY_KEY_ID
*is* set but isn't a `rzp_test_...` key, this code never even runs —
config.py refuses to let the process start at all (see config.py and
DECISIONS.md's Stage 5 entry).

Stage 6: a network timeout talking to Razorpay does not tell us whether
the order was actually created on their side or not — the request may
have reached them and succeeded, with only the *response* lost. Blindly
retrying a plain `order.create()` call in that situation risks a second,
duplicate order for the same human-approved transaction. `receipt` is
the idempotency key that makes retrying safe: before ever calling
`order.create()`, this looks up whether an order with this exact receipt
already exists (Razorpay's Orders list API supports filtering by
`receipt`) and returns that instead of creating a second one. Both the
lookup and the create call are individually retried (with a bounded
number of attempts and a short backoff) for the transient, ambiguous
failures — timeouts, connection errors, Razorpay-side 5xxs — where
retrying is actually the right move; a definite client error (a bad
amount, a malformed request) is not retried, since it will fail
identically every time and retrying it only burns the attempt budget on
a call whose outcome is already known.

Callers are expected to pass a `receipt` that's stable across retries of
the *same* logical transaction — service.py derives it from the approval
queue's `request_id`, which is minted once per NEEDS_HUMAN request and
never changes across however many times execution is retried (see
service.execute_approval() and approval_queue.py's Stage 6 entry).
"""

from __future__ import annotations

import time

from darwaza import config

# Bounded retry policy. Not configurable via env vars deliberately — this
# is demo/test-mode traffic, not a production SLA to tune; a fixed,
# named policy is honest about what's actually been exercised.
MAX_ATTEMPTS = 3
REQUEST_TIMEOUT_SECONDS = 10
# Sleep between attempt 1->2 and 2->3 respectively; nothing sleeps after
# the final attempt, since there's nothing left to wait for.
_RETRY_BACKOFF_SECONDS = (0.5, 1.5)


class ExecutionError(RuntimeError):
    """create_order() made every attempt its retry policy allows and
    never got a definite success — distinct from the "keys not
    configured" RuntimeError below, which is a config problem discovered
    on the very first attempt, with no retry at all (retrying a call
    that will fail identically every time wastes the attempt budget for
    no benefit). Subclasses RuntimeError so existing `except RuntimeError`
    call sites still catch both without change."""


def _is_retryable(exc: Exception) -> bool:
    """True for failures where we genuinely don't know whether Razorpay
    received/processed the request (a timeout, a dropped connection, a
    Razorpay-side 5xx) — retrying is the right move for those, backed by
    the receipt lookup above so a retry can't itself create a duplicate.
    False for a definite client-side rejection (`BadRequestError`, e.g. a
    bad amount or currency): Razorpay understood the request and refused
    it for a reason that won't change between attempts."""
    import requests.exceptions
    from razorpay.errors import GatewayError, ServerError

    return isinstance(
        exc,
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            GatewayError,
            ServerError,
        ),
    )


def _find_existing_order(client, receipt: str) -> dict | None:
    """The idempotency-by-receipt lookup: has an order with this exact
    receipt already been created (by a prior attempt whose response we
    never saw)? Defensively re-checks the `receipt` field on whatever
    comes back rather than trusting the API's own filter unconditionally
    — the same "don't just trust the query worked" caution this project
    applies elsewhere (see DECISIONS.md)."""
    existing = client.order.all({"receipt": receipt, "count": 1}, timeout=REQUEST_TIMEOUT_SECONDS)
    for item in existing.get("items", []):
        if item.get("receipt") == receipt:
            return item
    return None


def create_order(amount_rupees: float, *, currency: str = "INR", receipt: str | None = None) -> dict:
    """Create (or, idempotently, find) a Razorpay test-mode order for
    `amount_rupees`, configured to auto-capture once a payment is made
    against it.

    IMPORTANT — what this does NOT do: it does not itself move money or
    simulate a card/UPI payment. Actually completing a payment against
    this order requires Razorpay's Checkout (a real frontend flow, out of
    scope here — Darwaza is the authorization gateway, not a checkout
    UI, see DECISIONS.md's problem statement) or Razorpay's test-mode
    payment-simulation API called separately. "Order create + capture"
    in the build plan means: a real order exists in Razorpay's test
    environment, correctly configured, proving the authorization
    decision actually reaches a real payment processor — not that a full
    payment round-trip happened headlessly.

    Raises `RuntimeError` immediately (no retry) if RAZORPAY_KEY_ID/
    RAZORPAY_KEY_SECRET aren't configured, or `ExecutionError` (a
    RuntimeError subclass) if every retry attempt against a configured,
    reachable-in-principle Razorpay was exhausted without a definite
    result. Either way, the caller (service.py) never sees a call that
    silently no-ops or silently double-creates.
    """
    key_id = config.RAZORPAY_KEY_ID
    key_secret = config.RAZORPAY_KEY_SECRET
    if not key_id or not key_secret:
        raise RuntimeError(
            "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. Get test-mode "
            "keys from the Razorpay dashboard (Settings -> API Keys) and set "
            "them as environment variables before executing a transaction."
        )

    import razorpay  # local import: keep this an optional dependency

    client = razorpay.Client(auth=(key_id, key_secret))

    amount_paise = int(round(amount_rupees * 100))  # Razorpay amounts are in paise

    last_error: Exception | None = None
    attempt = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            if receipt:
                found = _find_existing_order(client, receipt)
                if found is not None:
                    return found

            return client.order.create(
                {
                    "amount": amount_paise,
                    "currency": currency,
                    "receipt": receipt,
                    "payment_capture": 1,
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 -- deliberately broad, see _is_retryable
            last_error = exc
            if attempt == MAX_ATTEMPTS or not _is_retryable(exc):
                break
            time.sleep(_RETRY_BACKOFF_SECONDS[attempt - 1])

    raise ExecutionError(
        f"Razorpay order creation failed after {attempt} attempt(s) "
        f"(receipt={receipt!r}): {last_error}"
    ) from last_error
