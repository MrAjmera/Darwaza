"""Unit tests for evaluate(): one passing and one failing case per check."""

from datetime import datetime, timedelta, timezone

import pytest

from darwaza import keys
from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)
PAST = datetime.now(timezone.utc) - timedelta(days=1)


def _signed(mandate: NormalizedMandate) -> NormalizedMandate:
    """Return `mandate` with a real signature over its current fields —
    what a legitimate signer would have produced. Every helper below
    signs by default so every existing test still exercises "a validly
    signed mandate," which is what makes it a fair test of the *other*
    checks; tests for the signature check itself pass an explicit
    (invalid) `signature=` override instead, which skips this."""
    return mandate.model_copy(update={"signature": keys.sign(mandate.signing_payload())})


def ap2_mandate(**overrides) -> NormalizedMandate:
    defaults = dict(
        mandate_id="ap2-1",
        principal_id="p1",
        expiry=FUTURE,
        signature="unsigned-placeholder",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )
    defaults.update(overrides)
    m = NormalizedMandate(**defaults)
    return m if "signature" in overrides else _signed(m)


def acp_token(**overrides) -> NormalizedMandate:
    defaults = dict(
        mandate_id="acp-1",
        principal_id="p1",
        expiry=FUTURE,
        signature="unsigned-placeholder",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    defaults.update(overrides)
    m = NormalizedMandate(**defaults)
    return m if "signature" in overrides else _signed(m)


def tx(**overrides) -> ProposedTransaction:
    defaults = dict(merchant_id="merchant-a", amount=50.0, category="electronics")
    defaults.update(overrides)
    return ProposedTransaction(**defaults)


# a. signature
def test_signature_valid_passes():
    m = ap2_mandate()  # signed by the default helper
    result = evaluate(m, tx(amount=100), set())
    assert result.failed_check != "signature"


def test_signature_garbage_fails():
    m = ap2_mandate(signature="not-a-real-signature")
    result = evaluate(m, tx(amount=100), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "signature"


def test_signature_tampered_field_fails():
    # Sign a mandate honestly, then mutate a field afterward — simulating
    # an attacker who intercepts a valid mandate and raises their own cap.
    # model_copy() changes the field without re-signing, so the signature
    # no longer matches what verify_signature() re-derives.
    m = ap2_mandate(max_amount=1000.0)
    tampered = m.model_copy(update={"max_amount": 999999.0})
    result = evaluate(tampered, tx(amount=50000.0), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "signature"


# b. expiry
def test_expiry_pass():
    m = ap2_mandate(expiry=FUTURE)
    result = evaluate(m, tx(amount=100), set())
    assert result.failed_check != "expiry"


def test_expiry_fail():
    m = ap2_mandate(expiry=PAST)
    result = evaluate(m, tx(amount=100), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "expiry"


# c. replay
def test_replay_pass_when_nonce_unseen():
    m = ap2_mandate(mandate_id="fresh-nonce")
    result = evaluate(m, tx(amount=100), seen_nonces=set())
    assert result.failed_check != "replay"


def test_replay_fail_when_nonce_seen():
    m = ap2_mandate(mandate_id="used-nonce")
    result = evaluate(m, tx(amount=100), seen_nonces={"used-nonce"})
    assert result.outcome == "DENY"
    assert result.failed_check == "replay"


# d. merchant match (ACP-style only)
def test_merchant_match_pass():
    m = acp_token(merchant_id="merchant-a")
    result = evaluate(m, tx(merchant_id="merchant-a", amount=50.0), set())
    assert result.failed_check != "merchant_match"


def test_merchant_match_fail():
    m = acp_token(merchant_id="merchant-a")
    result = evaluate(m, tx(merchant_id="merchant-b", amount=50.0), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "merchant_match"


def test_merchant_match_skipped_for_ap2_style():
    # AP2 mandates don't bind a merchant at all — any merchant should pass
    # this check (though other checks may still apply).
    m = ap2_mandate()
    result = evaluate(m, tx(merchant_id="whatever-merchant", amount=100), set())
    assert result.failed_check != "merchant_match"


# e. amount cap
def test_amount_cap_pass_ap2_under_max():
    m = ap2_mandate(max_amount=1000.0)
    result = evaluate(m, tx(amount=999.0), set())
    assert result.failed_check != "amount_cap"


def test_amount_cap_fail_ap2_over_max():
    m = ap2_mandate(max_amount=1000.0)
    result = evaluate(m, tx(amount=1001.0), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "amount_cap"


def test_amount_cap_fail_acp_mismatch():
    m = acp_token(exact_amount=50.0)
    result = evaluate(m, tx(amount=50.01), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "amount_cap"


# f. category scope (AP2-style only)
def test_category_scope_pass():
    m = ap2_mandate(category_scope=["electronics", "books"])
    result = evaluate(m, tx(category="books", amount=100), set())
    assert result.failed_check != "category_scope"


def test_category_scope_fail():
    m = ap2_mandate(category_scope=["electronics"])
    result = evaluate(m, tx(category="groceries", amount=100), set())
    assert result.outcome == "DENY"
    assert result.failed_check == "category_scope"


def test_category_scope_skipped_for_acp_style():
    # ACP tokens never state a category — nothing to check.
    m = acp_token()
    result = evaluate(m, tx(category=None, amount=50.0), set())
    assert result.failed_check != "category_scope"


def test_full_allow_ap2():
    m = ap2_mandate()
    result = evaluate(m, tx(amount=500.0, category="electronics"), set())
    assert result.outcome == "ALLOW"
    assert result.failed_check is None


def test_full_allow_acp():
    m = acp_token()
    result = evaluate(m, tx(merchant_id="merchant-a", amount=50.0), set())
    assert result.outcome == "ALLOW"
    assert result.failed_check is None


# g. human review threshold (AP2-style only)
def test_needs_human_when_ap2_amount_exceeds_review_threshold():
    m = ap2_mandate(max_amount=1000.0, category_scope=["electronics"])
    result = evaluate(m, tx(amount=800.0, category="electronics"), set())
    assert result.outcome == "NEEDS_HUMAN"
    assert result.failed_check == "human_review_threshold"


def test_ap2_amount_at_threshold_boundary_still_auto_allows():
    # Exactly 50% of the cap is the boundary — the check uses a strict
    # ">" so the boundary itself still auto-allows.
    m = ap2_mandate(max_amount=1000.0, category_scope=["electronics"])
    result = evaluate(m, tx(amount=500.0, category="electronics"), set())
    assert result.outcome == "ALLOW"


def test_acp_never_needs_human_regardless_of_amount():
    # ACP tokens are exact-amount and single-use — there is no "fraction
    # of a ceiling" for them, so this check must never apply.
    m = acp_token(exact_amount=999.0)
    result = evaluate(m, tx(merchant_id="merchant-a", amount=999.0), set())
    assert result.outcome == "ALLOW"
