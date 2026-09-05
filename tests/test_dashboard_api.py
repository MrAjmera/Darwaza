"""Tests for the dashboard-only endpoints (GET /v1/audit-log, POST
/v1/demo/simulate/{scenario}) added to api.py. Same fixture pattern as
test_api.py: isolated tmp_path state per test, dependency_overrides
cleared after.

These endpoints exist purely for dashboard/ to consume -- see api.py's
own module comments above them. Nothing here exercises evaluate() or
service.py in a way test_api.py/test_simulate.py don't already cover;
these tests are about the JSON shape and the "click twice" replay
behavior the dashboard specifically depends on.
"""

from __future__ import annotations

import os

os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("RAZORPAY_KEY_ID", None)
os.environ.pop("RAZORPAY_KEY_SECRET", None)

import pytest
from fastapi.testclient import TestClient

from darwaza.api import _approval_db_path, _log_path, _nonce_db_path, _rate_limiter, app
from darwaza.rate_limit import RateLimiter


@pytest.fixture
def client(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"
    generous_limiter = RateLimiter(capacity=1000, refill_rate_per_second=1000)

    app.dependency_overrides[_log_path] = lambda: log_path
    app.dependency_overrides[_nonce_db_path] = lambda: nonce_db_path
    app.dependency_overrides[_approval_db_path] = lambda: approval_db_path
    app.dependency_overrides[_rate_limiter] = lambda: generous_limiter

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /v1/audit-log
# ---------------------------------------------------------------------------


def test_audit_log_empty_before_any_decision(client):
    response = client.get("/v1/audit-log")

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "total_entries": 0,
        "chain_intact": True,
        "chain_break_reason": None,
        "entries": [],
    }


def test_audit_log_reflects_a_real_decision_and_agrees_with_metrics(client):
    client.post(
        "/v1/demo/simulate/happy-path",
    )

    audit = client.get("/v1/audit-log").json()
    metrics = client.get("/metrics").json()

    assert audit["total_entries"] == 1
    assert audit["chain_intact"] is True
    assert audit["entries"][0]["outcome"] == "ALLOW"
    # Same underlying file, same verify_chain() call as /metrics -- the
    # two must never disagree about whether the chain is intact.
    assert audit["chain_intact"] == metrics["audit_log"]["chain_intact"]
    assert audit["total_entries"] == metrics["audit_log"]["entries"]


def test_audit_log_newest_first_and_limit_is_respected(client):
    for _ in range(3):
        client.post("/v1/demo/simulate/needs-human")

    audit = client.get("/v1/audit-log", params={"limit": 2}).json()

    assert audit["total_entries"] == 3
    assert len(audit["entries"]) == 2
    # Newest first: the two most recent seq numbers, highest seq at index 0.
    assert audit["entries"][0]["seq"] > audit["entries"][1]["seq"]


# ---------------------------------------------------------------------------
# POST /v1/demo/simulate/{scenario}
# ---------------------------------------------------------------------------


def test_demo_simulate_happy_path_allows(client):
    response = client.post("/v1/demo/simulate/happy-path")

    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "ALLOW"
    assert body["scenario"] == "happy-path"
    assert body["principal_id"] == "user-krishna"
    assert "proposed_tx" in body and body["proposed_tx"]["category"] == "books"


def test_demo_simulate_poisoned_catalog_denies_on_amount_cap(client):
    response = client.post("/v1/demo/simulate/poisoned-catalog")

    assert response.status_code == 403
    body = response.json()
    assert body["outcome"] == "DENY"
    assert body["failed_check"] == "amount_cap"
    # The buyer agent really did propose the inflated amount -- the gate
    # blocked it, it didn't just refuse to look at it.
    assert body["proposed_tx"]["amount"] == 999999


def test_demo_simulate_needs_human_returns_202_with_request_id(client):
    response = client.post("/v1/demo/simulate/needs-human")

    assert response.status_code == 202
    body = response.json()
    assert body["outcome"] == "NEEDS_HUMAN"
    assert body["failed_check"] == "human_review_threshold"
    assert body["request_id"]
    assert body["explanation"]


def test_demo_simulate_same_scenario_twice_does_not_collide_on_replay(client):
    """The whole reason api.py mints a fresh mandate_id per call: a
    dashboard button gets clicked more than once, and simulate.py's
    scenario functions default to one fixed id meant for a single CLI
    run. Both calls here must independently ALLOW, not the second one
    DENY on `replay`."""
    first = client.post("/v1/demo/simulate/happy-path")
    second = client.post("/v1/demo/simulate/happy-path")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["outcome"] == second.json()["outcome"] == "ALLOW"

    audit = client.get("/v1/audit-log").json()
    assert audit["total_entries"] == 2
    assert audit["chain_intact"] is True


def test_demo_simulate_unknown_scenario_returns_404(client):
    response = client.post("/v1/demo/simulate/not-a-real-scenario")

    assert response.status_code == 404
    body = response.json()
    assert body["error"] == "unknown_scenario"
    assert "happy-path" in body["known_scenarios"]
