"""Normalized mandate shape that protocol-specific parsers map into.

See DECISIONS.md #1 for why we normalize instead of integrating one
protocol deeply.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class ProposedTransaction(BaseModel):
    """The transaction a buying agent is actually trying to execute.

    This is what gets checked *against* a mandate — it is not part of the
    mandate itself. It always carries a concrete merchant, amount, and
    category, regardless of which protocol produced the mandate.
    """

    merchant_id: str
    amount: float
    category: str | None = None


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class Decision(BaseModel):
    outcome: Outcome
    reason: str
    failed_check: str | None = None


class NormalizedMandate(BaseModel):
    """A mandate, normalized from either an AP2-style Intent Mandate or an
    ACP-style scoped token, into one shape the policy engine can check.

    The two source protocols authorize very differently:

    - AP2's Intent Mandate expresses *intent*: a principal authorizes an
      agent to spend up to `max_amount`, within a `category_scope`, without
      naming a specific merchant or exact amount up front. The mandate is
      a standing permission, not a receipt for one transaction.
    - ACP's scoped token expresses *narrow, exact permission*: it is
      single-use, bound to one `merchant_id` and one `exact_amount`, and
      says nothing about why the purchase is happening — there is no
      concept of "intent" or "category" in the token itself.

    This asymmetry is real and load-bearing, not an artifact of sloppy
    modeling — an ACP-style token genuinely cannot tell you what category
    of purchase it was meant for, because that protocol never asked. So
    the AP2-only fields below (`max_amount`, `category_scope`, `agent_id`)
    are all Optional with no default that fakes a value. A policy check
    that needs intent (e.g. "is this purchase in-scope for what the human
    actually authorized?") must be written to handle "we don't know" as a
    real case for ACP-style mandates, not silently treat missing intent as
    unlimited intent.
    """

    # Present on both shapes.
    mandate_id: str  # AP2: nonce/jti. ACP: single-use token id.
    principal_id: str
    expiry: datetime
    signature: str

    # AP2-only: expresses standing intent, not a bound transaction.
    agent_id: str | None = None
    max_amount: float | None = None
    category_scope: list[str] | None = None

    # ACP-only: expresses exact, merchant-bound, single-use permission.
    merchant_id: str | None = None
    exact_amount: float | None = None
