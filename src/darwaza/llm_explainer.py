"""The one place an LLM is allowed to run at all — strictly downstream
of a decision `policy_engine.evaluate()` already made. See DECISIONS.md
#6 for why this shape (a function that receives an already-final
Decision and returns a string) is a stronger guarantee than a policy
telling the model not to decide: the code path that could let it decide
doesn't exist here.

`explain()` is only ever called for a NEEDS_HUMAN decision — ALLOW/DENY
are already self-explanatory from `decision.reason`, and calling the LLM
for those would be the same enforcement-path involvement DECISIONS.md
#2 rules out, just moved one function later.
"""

from __future__ import annotations

import os

from darwaza.schema import Decision, NormalizedMandate, ProposedTransaction

_FALLBACK_TEMPLATE = (
    "[LLM explanation unavailable — no ANTHROPIC_API_KEY configured] "
    "Mandate {mandate_id} (principal {principal_id}) requests {amount} for "
    "merchant {merchant_id}{category_clause}, against a stated cap of "
    "{cap}. Flagged for human review because: {reason}"
)


def explain(
    mandate: NormalizedMandate, proposed_tx: ProposedTransaction, decision: Decision
) -> str:
    """Return a plain-language summary of a NEEDS_HUMAN decision for the
    human reviewer. Raises if called on anything but NEEDS_HUMAN — that
    restriction is deliberate, not defensive boilerplate: it's what keeps
    this function from ever being asked to explain (and thus, in a
    weaker implementation, drift toward influencing) an ALLOW or DENY.
    """
    if decision.outcome.value != "NEEDS_HUMAN":
        raise ValueError(
            "explain() only applies to NEEDS_HUMAN decisions — see DECISIONS.md #6. "
            f"Got outcome={decision.outcome.value}."
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _fallback(mandate, proposed_tx, decision)

    try:
        return _explain_with_llm(mandate, proposed_tx, decision, api_key)
    except Exception as exc:  # an explainer failure must never block review
        return _fallback(mandate, proposed_tx, decision) + f" (LLM explainer failed, using fallback: {exc})"


def _fallback(
    mandate: NormalizedMandate, proposed_tx: ProposedTransaction, decision: Decision
) -> str:
    category_clause = f" ({proposed_tx.category})" if proposed_tx.category else ""
    return _FALLBACK_TEMPLATE.format(
        mandate_id=mandate.mandate_id,
        principal_id=mandate.principal_id,
        amount=proposed_tx.amount,
        merchant_id=proposed_tx.merchant_id,
        category_clause=category_clause,
        cap=mandate.max_amount,
        reason=decision.reason,
    )


def _explain_with_llm(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    decision: Decision,
    api_key: str,
) -> str:
    import anthropic  # local import: keep this an optional dependency

    client = anthropic.Anthropic(api_key=api_key)
    prompt = (
        "You are writing a one or two sentence note for a human reviewer in "
        "a merchant's purchase-approval queue. A request was already flagged "
        "for human review by a deterministic rule, not by you — your only "
        "job is to explain plainly and neutrally why it was flagged and what "
        "the reviewer should look at. Do not recommend approve or deny.\n\n"
        f"Mandate: principal={mandate.principal_id}, cap={mandate.max_amount}, "
        f"category_scope={mandate.category_scope}\n"
        f"Requested transaction: merchant={proposed_tx.merchant_id}, "
        f"amount={proposed_tx.amount}, category={proposed_tx.category}\n"
        f"Deterministic flag reason: {decision.reason}"
    )
    message = client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=150,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text.strip()
