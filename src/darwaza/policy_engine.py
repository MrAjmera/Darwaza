"""Deterministic enforcement. See DECISIONS.md #2 for why there is no LLM
call anywhere in this file — every check here must be reproducible and
explainable by exact rule, not by a model's judgment.
"""

from __future__ import annotations

import math
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


class NonceClaimer(Protocol):
    """Structural type for the nonce registry evaluate() claims against.

    `claim(mandate_id) -> bool` must be a single atomic operation: True
    if *this* call is the one that reserved `mandate_id` (it was not
    already spent), False if someone else already claimed it. Both
    `nonce_store.NonceStore.claim()` (the CLI, persistent, backed by a
    SQLite PRIMARY KEY constraint) and a test double implementing the
    same atomic claim-once contract satisfy this.

    This replaces the old `NonceRegistry` protocol (a read-only
    `__contains__`, with the caller responsible for calling `.add()`
    afterward) — see DECISIONS.md for why fusing "check" and "claim"
    into one atomic call is necessary, and why that means `evaluate()`
    stops being a pure function as of this change."""

    def claim(self, mandate_id: str) -> bool: ...


def verify_signature(mandate: NormalizedMandate) -> bool:
    """Verify the mandate was signed, in full, by `mandate.principal_id`'s
    *own* registered demo keypair (darwaza.keys) — i.e. that every field
    on it is exactly what that specific principal signed, not a value an
    attacker added or changed afterward, and not a signature produced by
    some other principal's key.

    `mandate.signing_payload()` re-derives the same canonical bytes the
    signer produced; `keys.verify()` looks up `mandate.principal_id`'s
    registered public key and checks the signature against those bytes
    with *only that key*. Any mismatch — wrong/unregistered principal,
    wrong key, tampered field, malformed signature — returns False here,
    which the caller turns into a DENY.

    As of Stage 7 (DECISIONS.md), this is genuinely per-principal: before
    this stage every principal shared one demo keypair, so this check
    only ever proved "signed by *a* key this system trusts," never "signed
    by *this* principal's key" — a mandate signed for real but with its
    principal_id field changed to claim a different principal passed
    cleanly (see tests/test_attacks.py's forged-principal-id test). An
    unregistered principal_id is handled by evaluate() itself, as its own
    DENY reason (`failed_check="unknown_principal"`) *before* this
    function is even called, so it can be told apart from "registered
    principal, wrong signature" in the audit trail — see evaluate()'s
    check a0. This function alone doesn't distinguish the two: an
    unregistered principal simply has no key to check against and
    `keys.verify()` returns False for it here too, same as a bad
    signature would.
    """
    return keys.verify(mandate.principal_id, mandate.signing_payload(), mandate.signature)


def evaluate(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    nonce_claimer: NonceClaimer,
) -> Decision:
    """Run the mandate through every check in order, stopping at the first
    DENY. `nonce_claimer` is passed in explicitly (rather than being
    module-level state) so callers own the registry and its lifetime, and
    its persistence (an in-memory test double vs. `nonce_store.NonceStore`)
    is entirely the caller's choice.

    `evaluate()` is no longer a pure function: check g. below calls
    `nonce_claimer.claim()`, which mutates the claimer. That is
    deliberate — see DECISIONS.md's entry on this change. What's
    unchanged is *why* purity mattered in the first place: every branch
    here is still a plain, reproducible rule computed the same way every
    time from the same inputs, so the decision itself is exactly as
    deterministic and auditable as before. Determinism of the rules was
    always the actual goal; "no side effects" was one way to get there
    that stopped being compatible with closing D1 (see DECISIONS.md).

    This is the only place in the system allowed to produce NEEDS_HUMAN
    (see check f. and DECISIONS.md #5) — every branch here is a plain,
    reproducible rule. No model is called anywhere in this function; if
    an LLM-generated explanation is attached to a NEEDS_HUMAN decision,
    that happens strictly after this function returns, never inside it
    (DECISIONS.md #2).

    Check order, and why it's load-bearing:

    0. Amount validity — before anything else, including the mandate's
       own signature (see the comment at that check for why proposed_tx
       doesn't need the mandate to be trusted first).
    a0-f. Unknown principal, signature, expiry, merchant match, amount
       cap, category scope, human review threshold — every one of these
       can DENY (or, for f. only, route to NEEDS_HUMAN) without ever
       touching the nonce registry. A malformed or out-of-policy mandate
       must be rejected for free, as many times as an attacker cares to
       submit it.
    a0. Unknown principal runs *before* the signature check it's
       adjacent to, not after — a principal_id with no registered key
       (Stage 7, darwaza.keys) has no key to check the signature
       against at all, so there's nothing signature verification could
       even attempt; this check exists so that case gets its own
       specific DENY reason (`unknown_principal`) instead of being
       folded into a generic `signature` failure that would tell an
       audit-log reader "the signature was wrong" when the more precise
       (and more actionable) truth is "we don't know this principal."
    g. Replay/claim — LAST, on purpose. This used to run third (see the
       old check c.), which meant a mandate that was going to fail on
       amount or category *still* consumed its nonce on the way out.
       Once checking and claiming fuse into one atomic operation (this
       stage's fix for D1), that ordering becomes a denial-of-service
       primitive: an attacker who doesn't hold the principal's key can't
       forge a valid mandate, but they *can* replay someone else's
       legitimate mandate_id with an out-of-policy proposed_tx purely to
       burn the nonce before the real principal gets to use it. Running
       every other check first, and claiming only once we already know
       the mandate would otherwise ALLOW or NEEDS_HUMAN, closes that.
    """

    # Amount validity comes before check a., not after it. proposed_tx is
    # not part of the signed mandate — it's the buyer agent's own claim
    # about what it wants to buy — so confirming its shape doesn't require
    # trusting anything the signature proves, and there's no reason to do
    # the signature's public-key crypto on a request whose amount isn't
    # even a sane number. `proposed_tx.amount <= 0` alone is NOT a
    # sufficient guard: NaN is unordered, so `nan <= 0` is False and the
    # guard silently never fires — which is exactly how NaN (and 0.0 and
    # every negative amount) previously reached the amount cap and the
    # human-review threshold checks and satisfied both "not over the cap"
    # and "not over the human-review threshold" at once. `math.isfinite()`
    # rejects NaN and +/-inf explicitly, closing that gap. See
    # DECISIONS.md #8.
    if not math.isfinite(proposed_tx.amount) or proposed_tx.amount <= 0:
        return Decision(
            outcome=Outcome.DENY,
            reason=f"Transaction amount {proposed_tx.amount} is not a valid positive amount.",
            failed_check="invalid_amount",
        )

    # a0. Unknown principal: checked before the signature itself, and
    #     with its own DENY reason, so "we have no registered key for
    #     this principal at all" is distinguishable in the audit trail
    #     from "we have this principal's key and the signature doesn't
    #     match" (check a., below). Both ultimately mean "don't trust
    #     this mandate," but only one of them means "this principal_id
    #     isn't in our registry" — worth a panel/operator being able to
    #     tell apart at a glance. See keys.py and DECISIONS.md's Stage 7
    #     entry.
    if mandate.principal_id not in keys.PUBLIC_KEYS:
        return Decision(
            outcome=Outcome.DENY,
            reason=f"Principal '{mandate.principal_id}' is not a registered principal.",
            failed_check="unknown_principal",
        )

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

    # c. Merchant match only applies to ACP-style tokens, which bind to one
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

    # d. Amount cap: ACP tokens carry an exact amount (must match exactly —
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

    # e. Category scope only applies to AP2-style mandates — ACP tokens
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

    # f. Human review threshold (AP2-style mandates only): a mandate that
    #    structurally passed every check above still isn't necessarily
    #    safe to auto-approve if the request consumes most of the
    #    mandate's ceiling in one shot. ACP-style tokens are exact-amount
    #    and single-use — there's no "fraction of a ceiling" concept for
    #    them, so they never reach this branch (mandate.max_amount is
    #    None for a pure ACP token). This only decides what the outcome
    #    *would be* — the nonce isn't claimed until check g., below.
    needs_human_decision: Decision | None = None
    if mandate.max_amount is not None and mandate.exact_amount is None:
        if proposed_tx.amount > HUMAN_REVIEW_FRACTION_OF_CAP * mandate.max_amount:
            fraction = proposed_tx.amount / mandate.max_amount
            needs_human_decision = Decision(
                outcome=Outcome.NEEDS_HUMAN,
                reason=(
                    f"Transaction amount {proposed_tx.amount} is {fraction:.0%} of "
                    f"mandate cap {mandate.max_amount} — above the "
                    f"{HUMAN_REVIEW_FRACTION_OF_CAP:.0%} auto-approve threshold, "
                    "routed to human review."
                ),
                failed_check="human_review_threshold",
            )

    # g. Replay/claim — LAST, and atomic. Every check above has already
    #    passed (or produced a tentative NEEDS_HUMAN); only now do we
    #    reserve the nonce, in the same operation as checking it. A
    #    mandate that reaches here is either about to ALLOW or about to
    #    NEEDS_HUMAN — both outcomes mean this mandate_id is spoken for
    #    and must never be claimable again (see DECISIONS.md #9 for why
    #    NEEDS_HUMAN reserves too, and this stage's DECISIONS.md entry for
    #    why the claim itself had to become atomic and move here).
    if not nonce_claimer.claim(mandate.mandate_id):
        return Decision(
            outcome=Outcome.DENY,
            reason=f"Mandate {mandate.mandate_id} has already been used (replay).",
            failed_check="replay",
        )

    if needs_human_decision is not None:
        return needs_human_decision

    return Decision(
        outcome=Outcome.ALLOW,
        reason="All checks passed.",
        failed_check=None,
    )
