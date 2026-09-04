"""Tests for the HTTP API (api.py), covering every endpoint and every
documented status code.

Each test overrides api.py's path dependencies (_log_path,
_nonce_db_path, _approval_db_path — see api.py's module docstring for
why they're dependencies rather than module constants read directly)
to point at an isolated tmp_path, so tests never touch the real repo's
audit_log.jsonl/nonces.db/approvals.db regardless of which test module
darwaza.service happened to be imported by first. The rate limiter
(_rate_limiter) is overridden too, with a generous instance by default
so ordinary multi-call tests never get throttled by accident — the
dedicated rate-limiting tests below override it again, per-test, with a
tiny-capacity instance instead.
"""

from __future__ import annotations

import os

# Popped before any darwaza import, not after -- config.py resolves
# credentials once at first import, so this only works if it runs
# first. See config.py's module docstring.
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("RAZORPAY_KEY_ID", None)
os.environ.pop("RAZORPAY_KEY_SECRET", None)

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from darwaza import keys
from darwaza.api import _approval_db_path, _log_path, _nonce_db_path, _rate_limiter, app
from darwaza.rate_limit import RateLimiter
from darwaza.schema import NormalizedMandate

FUTURE = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _signed_mandate_dict(mandate_id: str, **overrides) -> dict:
    defaults = dict(
        mandate_id=mandate_id,
        principal_id="user-krishna",
        expiry=FUTURE,
        signature="placeholder",
        agent_id="agent-shopping-bot",
        max_amount=1000.0,
        category_scope=["electronics", "books"],
    )
    defaults.update(overrides)
    mandate = NormalizedMandate.model_validate(defaults)
    signed = mandate.model_copy(
        update={"signature": keys.sign(mandate.principal_id, mandate.signing_payload())}
    )
    return signed.model_dump(mode="json")


@pytest.fixture
def client(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"
    # Generous on purpose -- high enough that no test below that isn't
    # specifically testing rate limiting could plausibly hit it.
    generous_limiter = RateLimiter(capacity=1000, refill_rate_per_second=1000)

    app.dependency_overrides[_log_path] = lambda: log_path
    app.dependency_overrides[_nonce_db_path] = lambda: nonce_db_path
    app.dependency_overrides[_approval_db_path] = lambda: approval_db_path
    app.dependency_overrides[_rate_limiter] = lambda: generous_limiter

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /v1/authorize
# ---------------------------------------------------------------------------


def test_authorize_allow_returns_200(client):
    mandate = _signed_mandate_dict("api-allow-1")
    proposed_tx = {"merchant_id": "merchant-a", "amount": 500.0, "category": "electronics"}

    response = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})

    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "ALLOW"
    assert body["failed_check"] is None


def test_authorize_deny_returns_403_with_failed_check(client):
    mandate = _signed_mandate_dict("api-deny-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 1500.0, "category": "electronics"}

    response = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})

    assert response.status_code == 403
    body = response.json()
    assert body["outcome"] == "DENY"
    assert body["failed_check"] == "amount_cap"


def test_authorize_needs_human_returns_202_with_request_id_and_location(client):
    mandate = _signed_mandate_dict("api-needs-human-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}

    response = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})

    assert response.status_code == 202
    body = response.json()
    assert body["outcome"] == "NEEDS_HUMAN"
    assert body["request_id"]
    assert body["explanation"]
    assert response.headers["location"] == f"/v1/approvals/{body['request_id']}"


def test_authorize_malformed_body_returns_400(client):
    # amount=-500 violates ProposedTransaction's gt=0 constraint
    # (DECISIONS.md #8) -- this must never reach evaluate() at all.
    mandate = _signed_mandate_dict("api-malformed-1")
    proposed_tx = {"merchant_id": "merchant-a", "amount": -500.0, "category": "electronics"}

    response = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})

    assert response.status_code == 400
    assert response.json()["error"] == "malformed_request"


def test_authorize_missing_field_returns_400(client):
    mandate = _signed_mandate_dict("api-malformed-2")
    del mandate["expiry"]
    proposed_tx = {"merchant_id": "merchant-a", "amount": 100.0}

    response = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})

    assert response.status_code == 400


def test_authorize_replay_of_single_use_mandate_is_denied(client):
    # A pure ACP-style token: clear the AP2-only defaults
    # (_signed_mandate_dict's base fields) so this doesn't accidentally
    # get checked against a category_scope no ACP token ever states.
    mandate = _signed_mandate_dict(
        "api-replay-1",
        merchant_id="merchant-a",
        exact_amount=50.0,
        agent_id=None,
        max_amount=None,
        category_scope=None,
    )
    proposed_tx = {"merchant_id": "merchant-a", "amount": 50.0}

    first = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})
    assert first.status_code == 200

    second = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx})
    assert second.status_code == 403
    assert second.json()["failed_check"] == "replay"


# ---------------------------------------------------------------------------
# GET /v1/approvals, POST /v1/approvals/{id}/approve|deny
# ---------------------------------------------------------------------------


def test_list_approvals_shows_pending_request(client):
    mandate = _signed_mandate_dict("api-list-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    response = client.get("/v1/approvals")

    assert response.status_code == 200
    ids = [row["id"] for row in response.json()]
    assert request_id in ids


def test_approve_returns_200_and_records_audit_entry(client):
    mandate = _signed_mandate_dict("api-approve-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    response = client.post(f"/v1/approvals/{request_id}/approve")

    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "ALLOW"
    # No Razorpay keys configured in this test env -- must say so, not
    # silently pretend an order was created (DECISIONS.md #7).
    assert body["razorpay_order"] is None
    assert body["razorpay_error"] is not None


def test_deny_returns_200_with_deny_outcome(client):
    mandate = _signed_mandate_dict("api-deny-human-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    response = client.post(f"/v1/approvals/{request_id}/deny")

    assert response.status_code == 200
    assert response.json()["outcome"] == "DENY"


def test_approve_unknown_id_returns_404(client):
    response = client.post("/v1/approvals/does-not-exist/approve")
    assert response.status_code == 404


def test_approve_twice_returns_409_second_time(client):
    mandate = _signed_mandate_dict("api-double-approve-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    first = client.post(f"/v1/approvals/{request_id}/approve")
    assert first.status_code == 200

    second = client.post(f"/v1/approvals/{request_id}/approve")
    assert second.status_code == 409


# ---------------------------------------------------------------------------
# GET /v1/approvals/pending-execution, POST /v1/approvals/{id}/execute
# (Stage 6 — retrying execution for a request already approved but not
# yet executed against Razorpay)
# ---------------------------------------------------------------------------


def test_approved_request_appears_in_pending_execution_not_approvals(client):
    mandate = _signed_mandate_dict("api-pending-exec-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    # No Razorpay keys configured in this test env, so approve() cannot
    # actually execute -- the row must land in pending-execution, not
    # silently disappear.
    client.post(f"/v1/approvals/{request_id}/approve")

    pending_execution = client.get("/v1/approvals/pending-execution").json()
    ids = [row["id"] for row in pending_execution]
    assert request_id in ids

    still_pending = client.get("/v1/approvals").json()
    assert request_id not in [row["id"] for row in still_pending]


def test_execute_retries_and_reports_the_same_missing_key_error(client):
    mandate = _signed_mandate_dict("api-execute-retry-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]
    client.post(f"/v1/approvals/{request_id}/approve")

    response = client.post(f"/v1/approvals/{request_id}/execute")

    assert response.status_code == 200
    body = response.json()
    assert body["executed"] is False
    assert body["razorpay_order"] is None
    assert body["razorpay_error"] is not None

    # Still retryable -- unaffected by the failed attempt above.
    pending_execution = client.get("/v1/approvals/pending-execution").json()
    assert request_id in [row["id"] for row in pending_execution]


def test_execute_unknown_id_returns_404(client):
    response = client.post("/v1/approvals/does-not-exist/execute")
    assert response.status_code == 404


def test_execute_on_a_still_pending_request_returns_409(client):
    mandate = _signed_mandate_dict("api-execute-not-approved-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]

    # No approve()/deny() call -- a human hasn't decided this yet.
    response = client.post(f"/v1/approvals/{request_id}/execute")

    assert response.status_code == 409


def test_execute_on_a_denied_request_returns_409(client):
    mandate = _signed_mandate_dict("api-execute-denied-1", max_amount=1000.0)
    proposed_tx = {"merchant_id": "merchant-a", "amount": 800.0, "category": "electronics"}
    authorize_response = client.post(
        "/v1/authorize", json={"mandate": mandate, "proposed_tx": proposed_tx}
    )
    request_id = authorize_response.json()["request_id"]
    client.post(f"/v1/approvals/{request_id}/deny")

    response = client.post(f"/v1/approvals/{request_id}/execute")

    assert response.status_code == 409


# ---------------------------------------------------------------------------
# GET /healthz, GET /metrics
# ---------------------------------------------------------------------------


def test_healthz_returns_200(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_metrics_reflects_recorded_outcomes(client):
    allow_mandate = _signed_mandate_dict("api-metrics-allow-1")
    allow_tx = {"merchant_id": "merchant-a", "amount": 500.0, "category": "electronics"}
    client.post("/v1/authorize", json={"mandate": allow_mandate, "proposed_tx": allow_tx})

    deny_mandate = _signed_mandate_dict("api-metrics-deny-1", max_amount=1000.0)
    deny_tx = {"merchant_id": "merchant-a", "amount": 1500.0, "category": "electronics"}
    client.post("/v1/authorize", json={"mandate": deny_mandate, "proposed_tx": deny_tx})

    response = client.get("/metrics")

    assert response.status_code == 200
    body = response.json()
    # counters: in-process, from observability.COUNTERS (shared across
    # this whole test module's client fixture instances, hence >= not
    # ==, since other tests' decisions accumulate in the same process).
    assert body["counters"]["by_outcome"]["ALLOW"] >= 1
    assert body["counters"]["by_outcome"]["DENY"] >= 1
    assert body["counters"]["by_failed_check"].get("amount_cap", 0) >= 1
    # audit_log: durable, derived from this test's own isolated log file.
    assert body["audit_log"]["entries"] >= 2
    assert body["audit_log"]["chain_intact"] is True


# ---------------------------------------------------------------------------
# Rate limiting (429)
# ---------------------------------------------------------------------------


def test_authorize_rate_limited_returns_429_with_retry_after(client):
    # A capacity-1 limiter for this test only -- the client fixture's
    # default is deliberately generous so it never interferes here.
    tiny_limiter = RateLimiter(capacity=1, refill_rate_per_second=0.0001)
    app.dependency_overrides[_rate_limiter] = lambda: tiny_limiter

    mandate = _signed_mandate_dict("api-rate-limit-1")
    tx = {"merchant_id": "merchant-a", "amount": 500.0, "category": "electronics"}

    first = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": tx})
    assert first.status_code == 200

    second = client.post("/v1/authorize", json={"mandate": mandate, "proposed_tx": tx})
    assert second.status_code == 429
    assert second.json()["error"] == "rate_limited"
    assert int(second.headers["retry-after"]) >= 1


def test_rate_limit_is_keyed_per_agent_and_mandate_not_globally(client):
    """Two different (agent, mandate) pairs must not share one budget --
    exhausting one must not throttle the other."""
    tiny_limiter = RateLimiter(capacity=1, refill_rate_per_second=0.0001)
    app.dependency_overrides[_rate_limiter] = lambda: tiny_limiter

    mandate_a = _signed_mandate_dict("api-rate-limit-a", agent_id="agent-a")
    mandate_b = _signed_mandate_dict("api-rate-limit-b", agent_id="agent-b")
    tx = {"merchant_id": "merchant-a", "amount": 500.0, "category": "electronics"}

    exhaust = client.post("/v1/authorize", json={"mandate": mandate_a, "proposed_tx": tx})
    assert exhaust.status_code == 200

    throttled = client.post("/v1/authorize", json={"mandate": mandate_a, "proposed_tx": tx})
    assert throttled.status_code == 429

    other_pair = client.post("/v1/authorize", json={"mandate": mandate_b, "proposed_tx": tx})
    assert other_pair.status_code == 200  # different agent+mandate -- untouched budget
