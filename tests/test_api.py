"""Tests for the HTTP API (api.py), covering every endpoint and every
documented status code.

Each test overrides api.py's path dependencies (_log_path,
_nonce_db_path, _approval_db_path — see api.py's module docstring for
why they're dependencies rather than module constants read directly)
to point at an isolated tmp_path, so tests never touch the real repo's
audit_log.jsonl/nonces.db/approvals.db regardless of which test module
darwaza.service happened to be imported by first.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from darwaza import keys
from darwaza.api import _approval_db_path, _log_path, _nonce_db_path, app
from darwaza.schema import NormalizedMandate

FUTURE = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

# Force the fallback explainer / no real Razorpay calls in tests.
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("RAZORPAY_KEY_ID", None)
os.environ.pop("RAZORPAY_KEY_SECRET", None)


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
    signed = mandate.model_copy(update={"signature": keys.sign(mandate.signing_payload())})
    return signed.model_dump(mode="json")


@pytest.fixture
def client(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"

    app.dependency_overrides[_log_path] = lambda: log_path
    app.dependency_overrides[_nonce_db_path] = lambda: nonce_db_path
    app.dependency_overrides[_approval_db_path] = lambda: approval_db_path

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
    assert body["outcomes"]["ALLOW"] >= 1
    assert body["outcomes"]["DENY"] >= 1
    assert body["failed_checks"].get("amount_cap", 0) >= 1
    assert body["audit_chain_intact"] is True
