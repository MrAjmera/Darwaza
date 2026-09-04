"""Unit tests for razorpay_client.py: the fail-loudly-without-keys
behavior, and (Stage 6) the retry/timeout/idempotency-by-receipt logic
around create_order().

No live Razorpay call is exercised anywhere here — that requires real
test-mode keys the user supplies themselves (see README). The Stage 6
tests below exercise real retry/idempotency *logic* against a fake
`razorpay.Client` (monkeypatched onto the real, installed `razorpay`
module so the real `razorpay.errors` classes are what's actually raised
and caught) rather than a live network call; `pytest.importorskip`
keeps this file collectible (skipped, not erroring) in an environment
where `razorpay` isn't installed at all, matching the "genuinely
optional dependency" story in config.py/README.

As of Stage 5, create_order() reads its keys from config.py, which
resolves them from os.environ once at import time -- not per call. So
`monkeypatch.delenv(...)` (which only affects os.environ dynamically)
has no effect on what create_order() actually sees any more;
`monkeypatch.setattr(config, "RAZORPAY_KEY_ID", ...)` is what reaches
it, since razorpay_client.py does `from darwaza import config` and
reads `config.RAZORPAY_KEY_ID` at call time (an attribute lookup on the
live config module), not a name bound once at its own import time. See
config.py's module docstring for why every module keeps this pattern.
"""

from __future__ import annotations

import pytest

from darwaza import config, razorpay_client

razorpay = pytest.importorskip("razorpay")

import requests.exceptions  # noqa: E402 -- after importorskip, deliberately


def test_raises_without_keys(monkeypatch):
    monkeypatch.setattr(config, "RAZORPAY_KEY_ID", None)
    monkeypatch.setattr(config, "RAZORPAY_KEY_SECRET", None)

    with pytest.raises(RuntimeError, match="RAZORPAY_KEY_ID"):
        razorpay_client.create_order(100.0)


# ---------------------------------------------------------------------------
# Stage 6: retry, timeout, idempotency-by-receipt
# ---------------------------------------------------------------------------


class _FakeOrderResource:
    """Stands in for `razorpay.Client().order` -- records every call it
    receives and replays a scripted sequence of results/exceptions for
    `.create()`, so a test can assert exactly how many attempts a given
    failure sequence produced."""

    def __init__(self, *, existing_items=None, create_outcomes=None):
        self.all_calls: list[dict] = []
        self.create_calls: list[dict] = []
        self._existing_items = existing_items or []
        self._create_outcomes = list(create_outcomes or [])

    def all(self, params, **kwargs):
        self.all_calls.append(params)
        return {"items": self._existing_items}

    def create(self, data, **kwargs):
        self.create_calls.append(data)
        outcome = self._create_outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeClient:
    def __init__(self, *, order_resource, auth=None):
        self.order = order_resource


def _patch_client(monkeypatch, order_resource) -> None:
    monkeypatch.setattr(config, "RAZORPAY_KEY_ID", "rzp_test_fake")
    monkeypatch.setattr(config, "RAZORPAY_KEY_SECRET", "fake_secret")
    monkeypatch.setattr(
        razorpay, "Client", lambda auth=None: _FakeClient(order_resource=order_resource, auth=auth)
    )


def test_create_order_succeeds_on_first_attempt_no_retry(monkeypatch):
    resource = _FakeOrderResource(create_outcomes=[{"id": "order_first_try", "receipt": "r1"}])
    _patch_client(monkeypatch, resource)

    order = razorpay_client.create_order(100.0, receipt="r1")

    assert order["id"] == "order_first_try"
    assert len(resource.create_calls) == 1


def test_create_order_retries_transient_timeout_then_succeeds(monkeypatch):
    resource = _FakeOrderResource(
        create_outcomes=[
            requests.exceptions.Timeout("boom"),
            {"id": "order_second_try", "receipt": "r2"},
        ]
    )
    _patch_client(monkeypatch, resource)
    monkeypatch.setattr(razorpay_client, "_RETRY_BACKOFF_SECONDS", (0, 0))

    order = razorpay_client.create_order(100.0, receipt="r2")

    assert order["id"] == "order_second_try"
    assert len(resource.create_calls) == 2


def test_create_order_does_not_retry_bad_request_error(monkeypatch):
    from razorpay.errors import BadRequestError

    resource = _FakeOrderResource(create_outcomes=[BadRequestError("invalid amount")])
    _patch_client(monkeypatch, resource)
    monkeypatch.setattr(razorpay_client, "_RETRY_BACKOFF_SECONDS", (0, 0))

    with pytest.raises(razorpay_client.ExecutionError):
        razorpay_client.create_order(100.0, receipt="r3")

    # One attempt only -- a client error won't succeed on retry, so the
    # attempt budget isn't wasted on repeating it.
    assert len(resource.create_calls) == 1


def test_create_order_raises_execution_error_after_exhausting_retries(monkeypatch):
    resource = _FakeOrderResource(
        create_outcomes=[
            requests.exceptions.Timeout("1"),
            requests.exceptions.Timeout("2"),
            requests.exceptions.Timeout("3"),
        ]
    )
    _patch_client(monkeypatch, resource)
    monkeypatch.setattr(razorpay_client, "_RETRY_BACKOFF_SECONDS", (0, 0))

    with pytest.raises(razorpay_client.ExecutionError, match="3 attempt"):
        razorpay_client.create_order(100.0, receipt="r4")

    assert len(resource.create_calls) == razorpay_client.MAX_ATTEMPTS


def test_create_order_is_idempotent_by_receipt_finds_existing_order(monkeypatch):
    """The core idempotency guarantee: if an order with this exact
    receipt already exists (a prior attempt's response was lost, say),
    create_order() must return that one instead of ever calling
    order.create() again -- calling create() here would mean a
    duplicate order for the same human-approved transaction."""
    resource = _FakeOrderResource(
        existing_items=[{"id": "order_already_there", "receipt": "r5"}],
        create_outcomes=[AssertionError("order.create() should never be called")],
    )
    _patch_client(monkeypatch, resource)

    order = razorpay_client.create_order(100.0, receipt="r5")

    assert order["id"] == "order_already_there"
    assert resource.create_calls == []
    assert resource.all_calls == [{"receipt": "r5", "count": 1}]


def test_create_order_ignores_a_receipt_mismatch_from_the_lookup(monkeypatch):
    """Defence-in-depth: even if the lookup returns items, only an exact
    receipt match short-circuits create() -- a filter that behaved
    unexpectedly (or was ignored server-side) must not make this treat
    an unrelated order as "the same transaction, already done"."""
    resource = _FakeOrderResource(
        existing_items=[{"id": "order_unrelated", "receipt": "some-other-receipt"}],
        create_outcomes=[{"id": "order_new", "receipt": "r6"}],
    )
    _patch_client(monkeypatch, resource)

    order = razorpay_client.create_order(100.0, receipt="r6")

    assert order["id"] == "order_new"
    assert len(resource.create_calls) == 1


def test_create_order_without_receipt_skips_the_lookup(monkeypatch):
    resource = _FakeOrderResource(create_outcomes=[{"id": "order_no_receipt"}])
    _patch_client(monkeypatch, resource)

    order = razorpay_client.create_order(100.0, receipt=None)

    assert order["id"] == "order_no_receipt"
    assert resource.all_calls == []
