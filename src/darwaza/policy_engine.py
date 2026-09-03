"""Deterministic enforcement. See DECISIONS.md #2 for why there is no LLM
call anywhere in this file — every check here must be reproducible and
explainable by exact rule, not by a model's judgment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from darwaza import keys
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

# Fraction of an AP2-style mandate's max_amount ceiling above which a
# transaction routes to human review instead of auto-approving. AP2
# mandates express a *ceiling* for future purchases in a category, not
# permission for one specific transaction — spending most of that
# ceiling in a single request is exactly the case where "does this
# actually match what the principal meant to authorize" deserves a human
# glance rather than blind trust in the stated cap. See DECISIONS.md #5.
HUMAN_REVIEW_FRACTION_OF_CAP = 0.5


class NonceRegistry(Protocol):
    """Structural type for `seen_nonces`: anything supporting membership
    testing. Both a plain `set[str]` (tests) and `nonce_store.NonceStore`
    (the CLI, persistent) satisfy this — `evaluate()` never calls `.add()`
    itself, only the caller does, after a successful ALLOW, so `add` is
    deliberately not part of this protocol."""

    def __contains__(self, mandate_id: str) -> bool: ...


def verify_signature(mandate: NormalizedMandate) -> bool:
    """Verify the mandate was signed, in full, by the demo principal
    keypair (darwaza.keys) — i.e. that every field on it is exactly what
    the principal signed, not a value an attacker added or changed
    afterward.

    `mandate.signing_payload()` re-derives the same canonical bytes the
    signer produced; `keys.verify()` checks the signature against those
    bytes with the public key. Any mismatch — wrong key, tampered field,
    malformed signature — returns False here, which the caller turns into
    a DENY. See DECISIONS.md: this was the last stubbed check in the
    engine (previously always returned True).
    """
    return keys.verify(mandate.signing_payload(), mandate.signature)


def evaluate(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    seen_nonces: NonceRegistry,
) -> Decision:
    """Run the mandate through every check in order, stopping at the first
    DENY or NEEDS_HUMAN. `seen_nonces` is passed in explicitly (rather
    than being module-level state) so `evaluate` stays a pure function —
    no hidden mutation, callers own the registry and its lifetime, and
    its persistence (in-memory `set()` vs. `nonce_store.NonceStore`) is
    entirely the caller's choice — this function only ever reads it.

    This is the only place in the system allowed to produce NEEDS_HUMAN
    (see check g. and DECISIONS.md #5) — every branch here is a plain,
    reproducible rule. No model is called anywhere in this function; if
    an LLM-generated explanation is attached to a NEEDS_HUMAN decision,
    that happens strictly after this function returns, never inside it
    (DECISIONS.md #2).
    """

    # a. Signature must be valid, or nothing else about the mandate can be
    #    trusted — every later check is reading fields from a document we
    #    haven't confirmed the principal actually signed.
    if not verify_signature(mandate):
        return Decision(
            outcome=Outcome.DENY,
            reason="Mandate signature is invalid.",
            failed_check="signature",
        )

    # b. Expiry protects against a mandate being used long after the
    #    principal's authorization was meant to be valid.
    now = datetime.now(timezone.utc)
    if mandate.expiry <= now:
        return Decision(
            outcome=Outcome.DENY,
            reason=f"Mandate expired at {mandate.expiry.isoformat()}.",
            failed_check="expiry",
        )

    # c. Replay protection: a mandate (especially a single-use ACP token)
    #    must not be spent twice. We check membership, not just presence,
    #    because the caller is expected to add the id to the set after a
    #    successful ALLOW — evaluate() itself doesn't mutate seen_nonces.
    if mandate.mandate_id in seen_nonces:
        return Decision(
            outcome=Outcome.DENY,
            reason=f"Mandate {mandate.mandate_id} has already been used (replay).",
            failed_check="replay",
        )

    # d. Merchant match only applies to ACP-style tokens, which bind to one
    #    merchant. AP2-style mandates express intent without naming a
    #    merchant, so there's nothing to compare here — skip, don't fail.
    if mandate.merchant_id is not None:
        if mandate.merchant_id != proposed_tx.merchant_id:
            return Decision(
                outcome=Outcome.DENY,
                reason=(
                    f"Mandate is scoped to merchant '{mandate.merchant_id}' "
                    f"but transaction targets '{proposed_tx.merchant_id}'."
                ),
                failed_check="merchant_match",
            )

    # e. Amount cap: ACP tokens carry an exact amount (must match exactly —
    #    the token was issued for one specific purchase, not "up to").
    #    AP2 mandates carry a max_amount ceiling (transaction must be at or
    #    under it).
    if mandate.exact_amount is not None:
        if proposed_tx.amount != mandate.exact_amount:
            return Decision(
                outcome=Outcome.DENY,
                reason=(
                    f"Transaction amount {proposed_tx.amount} does not match "
                    f"token's exact amount {mandate.exact_amount}."
                ),
                failed_check="amount_cap",
            )
    elif mandate.max_amount is not None:
        if proposed_tx.amount > mandate.max_amount:
            return Decision(
                outcome=Outcome.DENY,
                reason=(
                    f"Transaction amount {proposed_tx.amount} exceeds mandate "
                    f"cap {mandate.max_amount}."
                ),
                failed_check="amount_cap",
            )

    # f. Category scope only applies to AP2-style mandates — ACP tokens
    #    never stated a category, so there's nothing to check it against.
    if mandate.category_scope is not None:
        if proposed_tx.category not in mandate.category_scope:
            return Decision(
                outcome=Outcome.DENY,
                reason=(
                    f"Category '{proposed_tx.category}' is not in mandate's "
                    f"scope {mandate.category_scope}."
                ),
                failed_check="category_scope",
            )

    # g. Human review threshold (AP2-style mandates only): a mandate that
    #    structurally passed every check above still isn't necessarily
    #    safe to auto-approve if the request consumes most of the
    #    mandate's ceiling in one shot. ACP-style tokens are exact-amount
    #    and single-use — there's no "fraction of a ceiling" concept for
    #    them, so they never reach this branch (mandate.max_amount is
    #    None for a pure ACP token).
    if mandate.max_amount is not None and mandate.exact_amount is None:
        if proposed_tx.amount > HUMAN_REVIEW_FRACTION_OF_CAP * mandate.max_amount:
            fraction = proposed_tx.amount / mandate.max_amount
            return Decision(
                outcome=Outcome.NEEDS_HUMAN,
                reason=(
                    f"Transaction amount {proposed_tx.amount} is {fraction:.0%} of "
                    f"mandate cap {mandate.max_amount} — above the "
                    f"{HUMAN_REVIEW_FRACTION_OF_CAP:.0%} auto-approve threshold, "
                    "routed to human review."
                ),
                failed_check="human_review_threshold",
            )

    return Decision(
        outcome=Outcome.ALLOW,
        reason="All checks passed.",
        failed_check=None,
    )
