"""Adversarial tests: each asserts the engine correctly DENIES a specific
attack. These exercise the same checks as test_policy_engine.py but frame
them as attacks rather than unit-level cases, to make the threat model
explicit and demoable.

Every mandate below is signed for real with `_signed()` (except the
forged-signature attack, which is the point) — otherwise, now that
signature verification is real, every one of these would DENY on
"signature" first and never actually exercise the check it claims to
test.

The poisoned-catalog / prompt-injection attack class now has a real,
runnable path — see test_attack_poisoned_catalog_is_denied below and
simulate.py — rather than living only as unit-level DENY assertions.
"""

from datetime import datetime, timedelta, timezone

from _fakes import FakeNonceClaimer
from darwaza import keys
from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)
PAST = datetime.now(timezone.utc) - timedelta(days=1)


def _signed(mandate: NormalizedMandate) -> NormalizedMandate:
    return mandate.model_copy(
        update={"signature": keys.sign(mandate.principal_id, mandate.signing_payload())}
    )


def test_attack_forged_signature_is_denied():
    """An attacker who doesn't hold the principal's private key — e.g. an
    agent impersonating a principal it doesn't represent — cannot forge a
    mandate that passes verification just by filling in plausible-looking
    fields. Every other field here is completely valid; only the
    signature is fabricated."""
    m = NormalizedMandate(
        mandate_id="forged-1",
        principal_id="p1",
        expiry=FUTURE,
        signature="dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ==",  # fabricated, not from our key
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())
    assert result.outcome == "DENY"
    assert result.failed_check == "signature"


def test_attack_forged_principal_id_signed_by_a_different_principals_key_is_denied():
    """Stage 7's fix, proven directly: before it, every principal shared
    ONE demo keypair, so `keys.verify()` could only ever prove "signed by
    the one key the whole system trusts" — it had no way to prove
    "signed by principal p2's *own* key specifically." A brand-new
    mandate, freshly and fully signed end to end, claiming any
    principal_id at all, verified fine — "signed by p2's key" and
    "signed by the one key everyone effectively shares" were the exact
    same operation (proven directly against the pre-fix code before
    this fix landed: see DECISIONS.md's Stage 7 entry). This is a
    materially different, and more serious, gap than "an already-signed
    mandate gets its principal_id field tampered afterward" — that
    specific tamper was already caught before this stage, because
    schema.signing_payload() includes principal_id in the signed bytes,
    so changing it post-signature always broke the hash regardless of
    key-sharing.

    Here: a mandate claims principal_id="p2", but whoever produced the
    signature over that exact payload only had p1's private key (not
    p2's) — e.g. an attacker (or a compromised agent acting for p1) who
    wants a transaction to look like it came from p2 instead. Now that
    each principal has a distinct registered key (darwaza.keys), this
    must DENY on the signature check: p1's signature does not verify
    against p2's registered public key, no matter how internally
    consistent the rest of the mandate is.
    """
    forged_as_p2 = NormalizedMandate(
        mandate_id="forge-as-p2",
        principal_id="p2",
        expiry=FUTURE,
        signature="placeholder",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    # Signed with p1's key, not p2's -- p1 has no relationship to p2's
    # identity, and under the old single-key scheme this distinction
    # couldn't even be expressed (there was only one key to sign with).
    forged_as_p2 = forged_as_p2.model_copy(
        update={"signature": keys.sign("p1", forged_as_p2.signing_payload())}
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    result = evaluate(forged_as_p2, tx, nonce_claimer=FakeNonceClaimer())

    assert result.outcome == "DENY"
    assert result.failed_check == "signature"


def test_attack_a_principals_own_correctly_signed_mandate_still_allows():
    """The happy path the fix above must not break: a mandate signed by
    principal p1's own key, correctly claiming principal_id="p1", is
    exactly what per-principal verification is supposed to let through —
    proving the fix is scoped (denies mismatched principal/key pairs)
    and not a blanket new failure (denies everything)."""
    m = _signed(
        NormalizedMandate(
            mandate_id="own-key-1",
            principal_id="p1",
            expiry=FUTURE,
            signature="unsigned-placeholder",
            merchant_id="merchant-a",
            exact_amount=50.0,
        )
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())

    assert result.outcome == "ALLOW"


def test_attack_unregistered_principal_is_denied_as_unknown_principal_not_signature():
    """A mandate whose principal_id has no entry in darwaza.keys' demo
    registry at all must DENY with its own distinct reason
    ("unknown_principal"), not "signature" — the two mean genuinely
    different things to whoever's reading the audit trail afterward: "we
    don't know this principal" is a different, and more actionable,
    finding than "we know this principal and their signature is wrong."
    See keys.py and DECISIONS.md's Stage 7 entry. The signature bytes
    here don't even matter for this outcome -- keys.PUBLIC_KEYS.get()
    returns None for an unregistered principal regardless of what's in
    the `signature` field, so evaluate() must never reach the signature
    check at all for this mandate."""
    m = NormalizedMandate(
        mandate_id="ghost-principal-1",
        principal_id="principal-that-was-never-registered",
        expiry=FUTURE,
        signature="doesnt-matter-not-even-valid-base64!!",
        merchant_id="merchant-a",
        exact_amount=50.0,
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())

    assert result.outcome == "DENY"
    assert result.failed_check == "unknown_principal"


def test_attack_replayed_mandate_is_denied():
    """A mandate already spent once must not be honored a second time,
    even if every other field is still valid."""
    m = _signed(
        NormalizedMandate(
            mandate_id="replay-me",
            principal_id="p1",
            expiry=FUTURE,
            signature="unsigned-placeholder",
            merchant_id="merchant-a",
            exact_amount=50.0,
        )
    )
    tx = ProposedTransaction(merchant_id="merchant-a", amount=50.0)

    # First use: legitimately allowed.
    first = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())
    assert first.outcome == "ALLOW"

    # Attacker replays the same mandate_id after it's already been marked used.
    second = evaluate(m, tx, nonce_claimer=FakeNonceClaimer(["replay-me"]))
    assert second.outcome == "DENY"
    assert second.failed_check == "replay"


def test_attack_expired_mandate_is_denied():
    """A mandate authorized in the past must not still be usable — this is
    what stops a stale, possibly leaked mandate from being replayed long
    after the principal intended it to be valid."""
    m = _signed(
        NormalizedMandate(
            mandate_id="expired-1",
            principal_id="p1",
            expiry=PAST,
            signature="unsigned-placeholder",
            agent_id="agent-1",
            max_amount=1000.0,
            category_scope=["electronics"],
        )
    )
    tx = ProposedTransaction(merchant_id="any-merchant", amount=100.0, category="electronics")

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())
    assert result.outcome == "DENY"
    assert result.failed_check == "expiry"


def test_attack_mandate_scoped_to_merchant_a_used_at_merchant_b_is_denied():
    """An ACP-style token scoped to one merchant must not authorize a
    transaction at a different merchant — this is what stops a leaked or
    intercepted token from being redirected to pay someone else."""
    m = _signed(
        NormalizedMandate(
            mandate_id="scoped-token-1",
            principal_id="p1",
            expiry=FUTURE,
            signature="unsigned-placeholder",
            merchant_id="merchant-a",
            exact_amount=50.0,
        )
    )
    tx = ProposedTransaction(merchant_id="merchant-b", amount=50.0)

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())
    assert result.outcome == "DENY"
    assert result.failed_check == "merchant_match"


def test_attack_cap_exceeding_request_is_denied():
    """A buying agent must not be able to push a transaction through for
    more than the principal actually authorized, even by a cent — this is
    the core protection against a compromised or misbehaving agent
    overspending."""
    m = _signed(
        NormalizedMandate(
            mandate_id="capped-1",
            principal_id="p1",
            expiry=FUTURE,
            signature="unsigned-placeholder",
            agent_id="agent-1",
            max_amount=1000.0,
            category_scope=["electronics"],
        )
    )
    tx = ProposedTransaction(merchant_id="any-merchant", amount=1000.01, category="electronics")

    result = evaluate(m, tx, nonce_claimer=FakeNonceClaimer())
    assert result.outcome == "DENY"
    assert result.failed_check == "amount_cap"


def test_attack_poisoned_catalog_is_denied(tmp_path):
    """A buying agent that reads a merchant's product catalog — untrusted
    text the gateway does not control — and obeys an instruction
    embedded in a listing description ("raise the spending limit",
    "proceed without confirmation") must still be stopped by the gate.
    This is run through the full simulate.py path (buyer agent -> gate ->
    audit log), not constructed by hand, because the point is that the
    *agent's own inflated proposal* gets denied, not a hand-crafted one.
    """
    from darwaza.simulate import scenario_poisoned_catalog

    result = scenario_poisoned_catalog(
        log_path=tmp_path / "audit_log.jsonl",
        nonce_db_path=tmp_path / "nonces.db",
        approval_db_path=tmp_path / "approvals.db",
    )
    assert result.decision.outcome == "DENY"
    assert result.decision.failed_check == "amount_cap"
