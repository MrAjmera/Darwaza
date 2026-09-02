"""Adversarial tests: each asserts the engine correctly DENIES a specific
attack. These exercise the same checks as test_policy_engine.py but frame
them as attacks rather than unit-level cases, to make the threat model
explicit and demoable.

Prompt-injection and poisoned-catalog attacks are out of scope here — they
require a buyer-agent simulator and an LLM call, neither of which exist in
this session's build.
"""

from datetime import datetime, timedelta, timezone

from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)
PAST = datetime.now(timezone.utc) - timedelta(days=1)


def test_attack_replayed_mandate_is_denied():
    """A mandate already spent once must not be honored a second time,
    even if every other field is still valid."""
    m = NormalizedMandate(
        mandate_id="replay-me",
        principal_id="p1",
        expiry=FUTURE,
        signature="sig",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    # First use: legitimately allowed.
    first = evaluate(m, tx, seen_nonces=set())
    assert first.outcome == "ALLOW"

    # Attacker replays the same mandate_id after it's already been marked used.
    second = evaluate(m, tx, seen_nonces={"replay-me"})
    assert second.outcome == "DENY"
    assert second.failed_check == "replay"


def test_attack_expired_mandate_is_denied():
    """A mandate authorized in the past must not still be usable — this is
    what stops a stale, possibly leaked mandate from being replayed long
    after the principal intended it to be valid."""
    m = NormalizedMandate(
        mandate_id="expired-1",
        principal_id="p1",
        expiry=PAST,
        signature="sig",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )
    tx = ProposedTransaction(merchant_id="any-merchant", amount=100.0, category="electronics")

    result = evaluate(m, tx, seen_nonces=set())
    assert result.outcome == "DENY"
    assert result.failed_check == "expiry"


def test_attack_mandate_scoped_to_merchant_a_used_at_merchant_b_is_denied():
    """An ACP-style token scoped to one merchant must not authorize a
    transaction at a different merchant — this is what stops a leaked or
    intercepted token from being redirected to pay someone else."""
    m = NormalizedMandate(
        mandate_id="scoped-token-1",
        principal_id="p1",
        expiry=FUTURE,
        signature="sig",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    tx = ProposedTransaction(merchant_id="merchant-b", amount=50.0)

    result = evaluate(m, tx, seen_nonces=set())
    assert result.outcome == "DENY"
    assert result.failed_check == "merchant_match"


def test_attack_cap_exceeding_request_is_denied():
    """A buying agent must not be able to push a transaction through for
    more than the principal actually authorized, even by a cent — this is
    the core protection against a compromised or misbehaving agent
    overspending."""
    m = NormalizedMandate(
        mandate_id="capped-1",
        principal_id="p1",
        expiry=FUTURE,
        signature="sig",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )
    tx = ProposedTransaction(merchant_id="any-merchant", amount=1000.01, category="electronics")

    result = evaluate(m, tx, seen_nonces=set())
    assert result.outcome == "DENY"
    assert result.failed_check == "amount_cap"
