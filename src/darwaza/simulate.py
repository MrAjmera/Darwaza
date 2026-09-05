"""Live end-to-end scenarios: buyer agent -> gate -> audit log ->
(NEEDS_HUMAN only) explain + enqueue.

tests/test_attacks.py constructs mandates and transactions directly and
asserts on evaluate()'s return value — good for unit-level proof, but it
skips the part that makes this a *system*: a buyer agent reading a real
(possibly poisoned) catalog and deciding what to propose. This module
runs that full path, which is what the pitch video demo and the
"attempt -> block -> audit log line" framing actually need.

Each scenario function: builds a signed mandate, asks buyer_agent for a
proposed transaction, and hands both to service.authorize() — the same
function cli.py and api.py call, so a scenario run through here goes
through the identical enforcement path a real request would. This used
to duplicate part of that path itself (evaluate + claim + log, but not
explain/enqueue, which cli.py's simulate() bolted on afterward,
separately, with its own copy of that logic); as of Stage 4 that
duplication is gone.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from darwaza import buyer_agent, keys, service
from darwaza.schema import NormalizedMandate, ProposedTransaction
from darwaza.service import AuthorizationResult

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
    return mandate.model_copy(
        update={"signature": keys.sign(mandate.principal_id, mandate.signing_payload())}
    )


def _run(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    *,
    log_path: Path,
    nonce_db_path: Path,
    approval_db_path: Path,
) -> AuthorizationResult:
    return service.authorize(
        mandate,
        proposed_tx,
        log_path=log_path,
        nonce_db_path=nonce_db_path,
        approval_db_path=approval_db_path,
    )


def scenario_happy_path(
    *,
    log_path: Path,
    nonce_db_path: Path,
    approval_db_path: Path,
    mandate_id: str = "sim-happy-1",
) -> AuthorizationResult:
    """A legitimate buyer agent, buying something ordinary and in-budget.
    Expected: ALLOW.

    `mandate_id` defaults to the fixed id every CLI run has always used
    (tests/docs reference it) -- api.py's POST /v1/demo/simulate/...
    endpoint overrides it with a fresh id per call, so a dashboard
    button can be clicked more than once without the second click
    hitting `replay` against the first click's already-claimed nonce.
    """
    mandate = _signed_mandate(mandate_id)
    proposed_tx = buyer_agent.decide_deterministic("books")
    return _run(
        mandate, proposed_tx, log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )


def scenario_poisoned_catalog(
    *,
    log_path: Path,
    nonce_db_path: Path,
    approval_db_path: Path,
    mandate_id: str = "sim-poisoned-1",
) -> AuthorizationResult:
    """A buyer agent that (as an unguarded LLM-based agent would) obeys
    an instruction embedded in a product description, inflating the
    transaction to 999,999. Expected: DENY on amount_cap — the mandate's
    real ceiling is enforced regardless of what the compromised agent
    proposed.

    See scenario_happy_path() for why `mandate_id` is overridable.
    """
    mandate = _signed_mandate(mandate_id)
    proposed_tx = buyer_agent.decide_deterministic(
        "electronics", obey_injected_instructions=True
    )
    return _run(
        mandate, proposed_tx, log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )


def scenario_large_purchase_needs_human(
    *,
    log_path: Path,
    nonce_db_path: Path,
    approval_db_path: Path,
    mandate_id: str = "sim-needs-human-1",
) -> AuthorizationResult:
    """A legitimate (non-attack) purchase that happens to consume most of
    the mandate's cap in one request — the NEEDS_HUMAN path, not an
    attack. Amount is picked directly (not via buyer_agent) because this
    scenario is about the threshold rule in policy_engine.py, not about
    catalog manipulation. Expected: NEEDS_HUMAN, failed_check
    "human_review_threshold". See scenario_happy_path() for why
    `mandate_id` is overridable.
    """
    mandate = _signed_mandate(mandate_id)
    proposed_tx = ProposedTransaction(
        merchant_id="merchant-bestbuy", amount=650.0, category="electronics"
    )
    return _run(
        mandate, proposed_tx, log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )


SCENARIOS = {
    "happy-path": scenario_happy_path,
    "poisoned-catalog": scenario_poisoned_catalog,
    "needs-human": scenario_large_purchase_needs_human,
}
