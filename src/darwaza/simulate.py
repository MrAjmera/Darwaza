"""Live end-to-end scenarios: buyer agent -> gate -> audit log.

tests/test_attacks.py constructs mandates and transactions directly and
asserts on evaluate()'s return value — good for unit-level proof, but it
skips the part that makes this a *system*: a buyer agent reading a real
(possibly poisoned) catalog and deciding what to propose. This module
runs that full path, which is what the pitch video demo and the
"attempt -> block -> audit log line" framing actually need.

Each scenario function: builds a signed mandate, asks buyer_agent for a
proposed transaction, runs it through policy_engine.evaluate(), records
the result to the audit log, and returns the Decision so a caller (the
CLI, or a test) can assert on it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from darwaza import buyer_agent, keys
from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import Decision, NormalizedMandate

PRINCIPAL_ID = "user-krishna"


def _signed_mandate(mandate_id: str, **overrides) -> NormalizedMandate:
    defaults = dict(
        mandate_id=mandate_id,
        principal_id=PRINCIPAL_ID,
        expiry=datetime.now(timezone.utc) + timedelta(days=1),
        signature="placeholder",
        agent_id="agent-shopping-bot",
        max_amount=1000.0,
        category_scope=["electronics", "books"],
    )
    defaults.update(overrides)
    mandate = NormalizedMandate(**defaults)
    return mandate.model_copy(update={"signature": keys.sign(mandate.signing_payload())})


class ScenarioResult:
    """What a scenario produced: the mandate id involved (so a caller can
    print/log it) and the Decision evaluate() returned."""

    def __init__(self, mandate_id: str, decision: Decision) -> None:
        self.mandate_id = mandate_id
        self.decision = decision


def _run(
    mandate: NormalizedMandate,
    proposed_tx,
    *,
    log_path: Path,
    nonce_db_path: Path,
) -> ScenarioResult:
    store = NonceStore(nonce_db_path)
    try:
        decision = evaluate(mandate, proposed_tx, store)
        if decision.outcome.value == "ALLOW":
            store.add(mandate.mandate_id)
    finally:
        store.close()

    append_entry(log_path, mandate.mandate_id, decision)
    return ScenarioResult(mandate.mandate_id, decision)


def scenario_happy_path(*, log_path: Path, nonce_db_path: Path) -> ScenarioResult:
    """A legitimate buyer agent, buying something ordinary and in-budget.
    Expected: ALLOW."""
    mandate = _signed_mandate("sim-happy-1")
    proposed_tx = buyer_agent.decide_deterministic("books")
    return _run(mandate, proposed_tx, log_path=log_path, nonce_db_path=nonce_db_path)


def scenario_poisoned_catalog(*, log_path: Path, nonce_db_path: Path) -> ScenarioResult:
    """A buyer agent that (as an unguarded LLM-based agent would) obeys
    an instruction embedded in a product description, inflating the
    transaction to 999,999. Expected: DENY on amount_cap — the mandate's
    real ceiling is enforced regardless of what the compromised agent
    proposed."""
    mandate = _signed_mandate("sim-poisoned-1")
    proposed_tx = buyer_agent.decide_deterministic(
        "electronics", obey_injected_instructions=True
    )
    return _run(mandate, proposed_tx, log_path=log_path, nonce_db_path=nonce_db_path)


SCENARIOS = {
    "happy-path": scenario_happy_path,
    "poisoned-catalog": scenario_poisoned_catalog,
}
