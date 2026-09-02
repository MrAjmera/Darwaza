"""Deterministic enforcement. See DECISIONS.md #2 for why there is no LLM
call anywhere in this file — every check here must be reproducible and
explainable by exact rule, not by a model's judgment.
"""

from __future__ import annotations

from datetime import datetime, timezone

from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction


def verify_signature(mandate: NormalizedMandate) -> bool:
    """Stub — always returns True.

    TODO: real Ed25519 signature verification. Tracked as an open item in
    DECISIONS.md. Until this is implemented, the "signature valid" check
    below is not actually protecting against a forged mandate.
    """
    return True


def evaluate(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    seen_nonces: set[str],
) -> Decision:
    """Run the mandate through every check in order, stopping at the first
    failure. `seen_nonces` is passed in explicitly (rather than being
    module-level state) so `evaluate` stays a pure function — no hidden
    mutation, callers own the set and its lifetime.

    NOTE: seen_nonces is in-memory only. It resets on process restart and
    won't be shared across multiple instances of this service — tracked as
    an open item in DECISIONS.md. Real replay protection needs persistent
    storage.
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

    return Decision(
        outcome=Outcome.ALLOW,
        reason="All checks passed.",
        failed_check=None,
    )
