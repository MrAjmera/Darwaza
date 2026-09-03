"""Unit tests for the downstream-only LLM explainer.

No ANTHROPIC_API_KEY is set in the test environment, so these exercise
the fallback path — which is deliberate: a live model call isn't
reproducible enough to assert on, and the fallback path is exactly what
this build actually runs without a configured key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from darwaza import llm_explainer
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)


def _mandate() -> NormalizedMandate:
    return NormalizedMandate(
        mandate_id="m1",
        principal_id="user-krishna",
        expiry=FUTURE,
        signature="sig",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )


def test_raises_for_allow_decision():
    decision = Decision(outcome=Outcome.ALLOW, reason="All checks passed.", failed_check=None)
    with pytest.raises(ValueError):
        llm_explainer.explain(_mandate(), ProposedTransaction(merchant_id="m", amount=1), decision)


def test_raises_for_deny_decision():
    decision = Decision(outcome=Outcome.DENY, reason="expired", failed_check="expiry")
    with pytest.raises(ValueError):
        llm_explainer.explain(_mandate(), ProposedTransaction(merchant_id="m", amount=1), decision)


def test_fallback_explanation_for_needs_human(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    decision = Decision(
        outcome=Outcome.NEEDS_HUMAN,
        reason="Transaction amount 800.0 is 80% of mandate cap 1000.0 — above threshold.",
        failed_check="human_review_threshold",
    )
    tx = ProposedTransaction(merchant_id="merchant-bestbuy", amount=800.0, category="electronics")

    explanation = llm_explainer.explain(_mandate(), tx, decision)

    assert "ANTHROPIC_API_KEY" in explanation  # clearly labeled as a fallback
    assert "800.0" in explanation
    assert "1000.0" in explanation
