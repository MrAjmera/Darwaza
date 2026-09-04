"""Generates evals/dataset.jsonl.

This is a build-time tool, not part of the eval run itself (evals/run.py
reads the committed dataset.jsonl; it does not call this). It exists
because every case needs a *real* Ed25519 signature over its exact
fields (except the forged-signature cases, which need a real *fake*
one) — hand-writing 40+ correct base64 signatures into a JSON file isn't
something a human should do by hand, and a dataset with wrong signatures
would silently test the wrong thing (every case would DENY on
"signature" instead of exercising the check each case claims to
target). Re-run this and commit the result any time a case is added or
changed:

    python evals/generate_dataset.py

Deterministic: darwaza.keys' demo keypairs are fixed, so running this
twice produces byte-identical output. No live network calls, no
API keys needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from darwaza import keys
from darwaza.schema import NormalizedMandate

FUTURE = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

FORGED_SIGNATURE = "dGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ=="  # base64, not from any registered key
UNREGISTERED_PRINCIPAL = "principal-not-in-the-registry"

CASES: list[dict] = []


def _mandate(
    mandate_id: str, principal_id: str, *, expiry: str = FUTURE, signature: str = "", **fields
) -> dict:
    """Build a mandate dict and sign it for real with `principal_id`'s
    own registered key, unless the caller already supplied a
    `signature` override (forged-signature / unknown-principal cases
    pass one explicitly and skip real signing)."""
    base = dict(mandate_id=mandate_id, principal_id=principal_id, expiry=expiry, **fields)
    if signature:
        base["signature"] = signature
        return base
    m = NormalizedMandate.model_validate({**base, "signature": "placeholder"})
    base["signature"] = keys.sign(principal_id, m.signing_payload())
    return base


def _tx(merchant_id: str, amount: float, category: str | None = None) -> dict:
    return {"merchant_id": merchant_id, "amount": amount, "category": category}


def _case(
    case_id: str,
    attack_class: str,
    mandate: dict,
    proposed_tx: dict,
    expected_outcome: str,
    expected_failed_check: str | None,
) -> None:
    CASES.append(
        {
            "case_id": case_id,
            "attack_class": attack_class,
            "mandate": mandate,
            "proposed_tx": proposed_tx,
            "expected_outcome": expected_outcome,
            "expected_failed_check": expected_failed_check,
        }
    )


# ---------------------------------------------------------------------------
# forged_signature — a fabricated signature over otherwise-valid fields.
# ---------------------------------------------------------------------------

_case(
    "forged-sig-ap2-1",
    "forged_signature",
    _mandate(
        "forged-sig-ap2-1", "p1", signature=FORGED_SIGNATURE,
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 100.0, "electronics"),
    "DENY", "signature",
)
_case(
    "forged-sig-acp-1",
    "forged_signature",
    _mandate("forged-sig-acp-1", "p2", signature=FORGED_SIGNATURE, merchant_id="merchant-a", exact_amount=50.0),
    _tx("merchant-a", 50.0),
    "DENY", "signature",
)
_case(
    "forged-sig-ap2-2",
    "forged_signature",
    _mandate(
        "forged-sig-ap2-2", "user-krishna", signature=FORGED_SIGNATURE,
        agent_id="agent-shopping-bot", max_amount=500.0, category_scope=["books"],
    ),
    _tx("merchant-bestbuy", 50.0, "books"),
    "DENY", "signature",
)

# ---------------------------------------------------------------------------
# unknown_principal — principal_id has no entry in darwaza.keys' registry.
# The signature field's content is irrelevant (evaluate() never reaches
# the signature check for these), so a plainly-fake string is enough.
# ---------------------------------------------------------------------------

_case(
    "unknown-principal-ap2-1",
    "unknown_principal",
    _mandate(
        "unknown-principal-ap2-1", UNREGISTERED_PRINCIPAL, signature="does-not-matter",
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 100.0, "electronics"),
    "DENY", "unknown_principal",
)
_case(
    "unknown-principal-acp-1",
    "unknown_principal",
    _mandate(
        "unknown-principal-acp-1", "ghost-principal-42", signature="does-not-matter",
        merchant_id="merchant-a", exact_amount=25.0,
    ),
    _tx("merchant-a", 25.0),
    "DENY", "unknown_principal",
)
_case(
    "unknown-principal-ap2-2",
    "unknown_principal",
    _mandate(
        "unknown-principal-ap2-2", "not-registered-either", signature="also-does-not-matter",
        agent_id="agent-2", max_amount=2000.0, category_scope=["groceries"],
    ),
    _tx("merchant-b", 300.0, "groceries"),
    "DENY", "unknown_principal",
)

# ---------------------------------------------------------------------------
# replay — a mandate legitimately used once (counted as legitimate
# traffic below), then replayed. Order matters: run.py processes the
# file top to bottom against one shared nonce claimer, so the "first
# use" row must appear before its "replay" row for this to mean anything.
# ---------------------------------------------------------------------------

_case(
    "replay-pair-1-first-use",
    "legitimate",
    _mandate(
        "replay-pair-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 200.0, "electronics"),
    "ALLOW", None,
)
_case(
    "replay-pair-1-replayed",
    "replay",
    _mandate(
        "replay-pair-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 200.0, "electronics"),
    "DENY", "replay",
)
_case(
    "replay-pair-2-first-use",
    "legitimate",
    _mandate("replay-pair-2", "p2", merchant_id="merchant-c", exact_amount=75.0),
    _tx("merchant-c", 75.0),
    "ALLOW", None,
)
_case(
    "replay-pair-2-replayed",
    "replay",
    _mandate("replay-pair-2", "p2", merchant_id="merchant-c", exact_amount=75.0),
    _tx("merchant-c", 75.0),
    "DENY", "replay",
)

# ---------------------------------------------------------------------------
# expired_mandate
# ---------------------------------------------------------------------------

_case(
    "expired-ap2-1",
    "expired_mandate",
    _mandate(
        "expired-ap2-1", "p1", expiry=PAST,
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 100.0, "electronics"),
    "DENY", "expiry",
)
_case(
    "expired-acp-1",
    "expired_mandate",
    _mandate("expired-acp-1", "p2", expiry=PAST, merchant_id="merchant-a", exact_amount=50.0),
    _tx("merchant-a", 50.0),
    "DENY", "expiry",
)
_case(
    "expired-ap2-2",
    "expired_mandate",
    _mandate(
        "expired-ap2-2", "user-krishna", expiry=PAST,
        agent_id="agent-shopping-bot", max_amount=5000.0, category_scope=["electronics", "books"],
    ),
    _tx("merchant-bestbuy", 200.0, "electronics"),
    "DENY", "expiry",
)

# ---------------------------------------------------------------------------
# cross_merchant_token_misuse — ACP-style tokens only (they bind a merchant).
# ---------------------------------------------------------------------------

_case(
    "cross-merchant-1",
    "cross_merchant_token_misuse",
    _mandate("cross-merchant-1", "p1", merchant_id="merchant-a", exact_amount=50.0),
    _tx("merchant-b", 50.0),
    "DENY", "merchant_match",
)
_case(
    "cross-merchant-2",
    "cross_merchant_token_misuse",
    _mandate("cross-merchant-2", "p2", merchant_id="merchant-amazon", exact_amount=120.0),
    _tx("merchant-flipkart", 120.0),
    "DENY", "merchant_match",
)
_case(
    "cross-merchant-3",
    "cross_merchant_token_misuse",
    _mandate("cross-merchant-3", "user-krishna", merchant_id="merchant-c", exact_amount=999.0),
    _tx("merchant-d", 999.0),
    "DENY", "merchant_match",
)

# ---------------------------------------------------------------------------
# amount_cap_violation
# ---------------------------------------------------------------------------

_case(
    "amount-cap-ap2-1",
    "amount_cap_violation",
    _mandate(
        "amount-cap-ap2-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 1000.01, "electronics"),
    "DENY", "amount_cap",
)
_case(
    "amount-cap-ap2-2",
    "amount_cap_violation",
    _mandate(
        "amount-cap-ap2-2", "p2", agent_id="agent-2", max_amount=200.0, category_scope=["books"],
    ),
    _tx("merchant-b", 5000.0, "books"),
    "DENY", "amount_cap",
)
_case(
    "amount-cap-acp-1",
    "amount_cap_violation",
    _mandate("amount-cap-acp-1", "user-krishna", merchant_id="merchant-a", exact_amount=50.0),
    _tx("merchant-a", 50.01),
    "DENY", "amount_cap",
)

# ---------------------------------------------------------------------------
# invalid_amount — proposed_tx.amount is not a valid positive finite
# number. These bypass ProposedTransaction's own Pydantic constraint
# (gt=0, allow_inf_nan=False) via model_construct() in run.py, on
# purpose — the point of this attack class is evaluate()'s OWN
# defence-in-depth check (DECISIONS.md #8), independent of whatever a
# caller's schema layer already validated. NaN/Infinity are valid JSON
# tokens to Python's json module (a non-standard but long-standing
# extension), so they're written here as literal `NaN`/`Infinity`.
# ---------------------------------------------------------------------------

_case(
    "invalid-amount-zero",
    "invalid_amount",
    _mandate(
        "invalid-amount-zero", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 0.0, "electronics"),
    "DENY", "invalid_amount",
)
_case(
    "invalid-amount-negative",
    "invalid_amount",
    _mandate(
        "invalid-amount-negative", "p2", agent_id="agent-2", max_amount=1000.0, category_scope=["books"],
    ),
    _tx("merchant-b", -250.0, "books"),
    "DENY", "invalid_amount",
)
_case(
    "invalid-amount-nan",
    "invalid_amount",
    _mandate(
        "invalid-amount-nan", "user-krishna",
        agent_id="agent-shopping-bot", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-bestbuy", float("nan"), "electronics"),
    "DENY", "invalid_amount",
)
_case(
    "invalid-amount-positive-infinity",
    "invalid_amount",
    _mandate(
        "invalid-amount-inf", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", float("inf"), "electronics"),
    "DENY", "invalid_amount",
)

# ---------------------------------------------------------------------------
# category_scope_violation — AP2-style only (ACP tokens never state one).
# ---------------------------------------------------------------------------

_case(
    "category-scope-1",
    "category_scope_violation",
    _mandate(
        "category-scope-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 100.0, "groceries"),
    "DENY", "category_scope",
)
_case(
    "category-scope-2",
    "category_scope_violation",
    _mandate(
        "category-scope-2", "p2", agent_id="agent-2", max_amount=500.0, category_scope=["books", "toys"],
    ),
    _tx("merchant-b", 50.0, "electronics"),
    "DENY", "category_scope",
)
_case(
    "category-scope-3",
    "category_scope_violation",
    _mandate(
        "category-scope-3", "user-krishna",
        agent_id="agent-shopping-bot", max_amount=5000.0, category_scope=["electronics", "books"],
    ),
    _tx("merchant-bestbuy", 400.0, "furniture"),
    "DENY", "category_scope",
)

# ---------------------------------------------------------------------------
# needs_human_threshold — legitimate but flagged: more than
# HUMAN_REVIEW_FRACTION_OF_CAP (0.5) of an AP2 mandate's ceiling in one
# request. Not an attack; a distinct third bucket from "attack" and
# "legitimate" in evals/run.py's report (see there).
# ---------------------------------------------------------------------------

_case(
    "needs-human-1",
    "needs_human_threshold",
    _mandate(
        "needs-human-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 800.0, "electronics"),
    "NEEDS_HUMAN", "human_review_threshold",
)
_case(
    "needs-human-2",
    "needs_human_threshold",
    _mandate(
        "needs-human-2", "p2", agent_id="agent-2", max_amount=2000.0, category_scope=["books"],
    ),
    _tx("merchant-b", 1500.0, "books"),
    "NEEDS_HUMAN", "human_review_threshold",
)
_case(
    "needs-human-3",
    "needs_human_threshold",
    _mandate(
        "needs-human-3", "user-krishna",
        agent_id="agent-shopping-bot", max_amount=5000.0, category_scope=["electronics", "books"],
    ),
    _tx("merchant-bestbuy", 4000.0, "electronics"),
    "NEEDS_HUMAN", "human_review_threshold",
)
_case(
    "needs-human-boundary-just-over",
    "needs_human_threshold",
    _mandate(
        "needs-human-boundary-just-over", "p1",
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 500.01, "electronics"),
    "NEEDS_HUMAN", "human_review_threshold",
)

# ---------------------------------------------------------------------------
# legitimate — must ALLOW. At least 25% of the whole corpus is this
# bucket (plus the two replay first-use cases above, also "legitimate").
# ---------------------------------------------------------------------------

_case(
    "legit-ap2-1",
    "legitimate",
    _mandate(
        "legit-ap2-1", "p1", agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 300.0, "electronics"),
    "ALLOW", None,
)
_case(
    "legit-ap2-2",
    "legitimate",
    _mandate(
        "legit-ap2-2", "p2", agent_id="agent-2", max_amount=2000.0, category_scope=["books", "toys"],
    ),
    _tx("merchant-b", 999.0, "toys"),
    "ALLOW", None,
)
_case(
    "legit-ap2-boundary-exactly-half",
    "legitimate",
    _mandate(
        "legit-ap2-boundary-exactly-half", "p1",
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics"],
    ),
    _tx("merchant-a", 500.0, "electronics"),
    "ALLOW", None,
)
_case(
    "legit-acp-1",
    "legitimate",
    _mandate("legit-acp-1", "p2", merchant_id="merchant-amazon", exact_amount=49.99),
    _tx("merchant-amazon", 49.99),
    "ALLOW", None,
)
_case(
    "legit-acp-2",
    "legitimate",
    _mandate("legit-acp-2", "user-krishna", merchant_id="merchant-flipkart", exact_amount=1500.0),
    _tx("merchant-flipkart", 1500.0),
    "ALLOW", None,
)
_case(
    "legit-acp-no-category",
    "legitimate",
    _mandate("legit-acp-no-category", "p1", merchant_id="merchant-c", exact_amount=10.0),
    _tx("merchant-c", 10.0, None),
    "ALLOW", None,
)
_case(
    "legit-ap2-small-purchase",
    "legitimate",
    _mandate(
        "legit-ap2-small-purchase", "p2",
        agent_id="agent-2", max_amount=10000.0, category_scope=["electronics", "books", "toys"],
    ),
    _tx("merchant-a", 25.0, "books"),
    "ALLOW", None,
)
_case(
    "legit-ap2-no-agent-id",
    "legitimate",
    # AP2 mandate with no distinct agent_id -- principal acts as its own
    # agent. rate_limit.py's agent_key fallback exists for exactly this
    # shape; evaluate() itself treats it no differently.
    _mandate("legit-ap2-no-agent-id", "user-krishna", max_amount=1000.0, category_scope=["groceries"]),
    _tx("merchant-a", 400.0, "groceries"),
    "ALLOW", None,
)
_case(
    "legit-ap2-multi-category-1",
    "legitimate",
    _mandate(
        "legit-ap2-multi-category-1", "p1",
        agent_id="agent-1", max_amount=1000.0, category_scope=["electronics", "groceries", "books"],
    ),
    _tx("merchant-a", 150.0, "groceries"),
    "ALLOW", None,
)
_case(
    "legit-ap2-multi-category-2",
    "legitimate",
    _mandate(
        "legit-ap2-multi-category-2", "p2",
        agent_id="agent-2", max_amount=1000.0, category_scope=["electronics", "groceries", "books"],
    ),
    _tx("merchant-b", 150.0, "books"),
    "ALLOW", None,
)
_case(
    "legit-acp-3",
    "legitimate",
    _mandate("legit-acp-3", "p1", merchant_id="merchant-d", exact_amount=2500.0),
    _tx("merchant-d", 2500.0),
    "ALLOW", None,
)
_case(
    "legit-ap2-just-under-cap",
    "legitimate",
    _mandate(
        "legit-ap2-just-under-cap", "user-krishna",
        agent_id="agent-shopping-bot", max_amount=100.0, category_scope=["electronics"],
    ),
    _tx("merchant-bestbuy", 49.99, "electronics"),
    "ALLOW", None,
)


def main() -> None:
    out_path = Path(__file__).resolve().parent / "dataset.jsonl"
    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        for case in CASES:
            f.write(json.dumps(case, sort_keys=False) + "\n")
    print(f"Wrote {len(CASES)} cases to {out_path}")


if __name__ == "__main__":
    main()
