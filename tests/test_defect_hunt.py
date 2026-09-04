"""Further defects found while auditing the codebase for the same family
of bugs as D1-D4 (TOCTOU races, and states that don't say what they mean).

D5 (amount validity) is fixed as of this file's current version -- see
DECISIONS.md #8 and policy_engine.py / schema.py. The other findings
below remain open (proven, not yet fixed).

Found, and ruled out (kept here as a record, not as failing tests):
- keys.verify() on malformed/truncated/wrong-length signatures: does NOT
  crash. base64.b64decode(..., validate=True) raises on bad base64, and
  Ed25519PublicKey.verify() with a wrong-length signature returns
  InvalidSignature (caught), not a different exception. Confirmed with a
  short-bytes signature and a truncated real signature -- both return
  False cleanly.
- schema.signing_payload() collisions between different mandates: every
  field except `signature` is included in the canonical JSON (nulls and
  all), with sorted keys and fixed separators -- no two structurally
  different NormalizedMandate values were found to serialize identically.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from darwaza import keys
from darwaza.approval_queue import ApprovalQueue
from darwaza.audit_log import append_entry, verify_chain
from darwaza.policy_engine import evaluate
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

FUTURE = datetime.now(timezone.utc) + timedelta(days=1)


def _signed_ap2_mandate(mandate_id: str, **overrides) -> NormalizedMandate:
    defaults = dict(
        mandate_id=mandate_id,
        principal_id="p1",
        expiry=FUTURE,
        signature="placeholder",
        agent_id="agent-1",
        max_amount=1000.0,
        category_scope=["electronics"],
    )
    defaults.update(overrides)
    m = NormalizedMandate(**defaults)
    return m.model_copy(update={"signature": keys.sign(m.signing_payload())})


# D5: proposed_tx.amount had no lower bound anywhere -- neither the
# schema nor evaluate() ever expressed "money flows from principal to
# merchant." Verified independently against the running code: 0.0,
# -1000.0, -999999.0, float('nan'), and float('-inf') ALL returned ALLOW
# against an AP2 mandate with max_amount=1000.0. Only float('inf') was
# (incidentally) denied, by check e.'s `>` comparison. NaN is the sharp
# case: it's unordered, so a naive `if amount <= 0: deny` guard would
# silently never fire for it -- `math.isfinite()` is required, not a
# comparison. See DECISIONS.md #8.
D5_INVALID_AMOUNTS = [0.0, -1000.0, -999999.0, float("nan"), float("-inf"), float("inf")]
D5_INVALID_AMOUNT_IDS = ["zero", "negative", "large-negative", "nan", "neg-inf", "pos-inf"]


@pytest.mark.parametrize("amount", D5_INVALID_AMOUNTS, ids=D5_INVALID_AMOUNT_IDS)
def test_D5_schema_rejects_non_finite_or_non_positive_amount(amount):
    """Defence-in-depth layer 1: ProposedTransaction itself should refuse
    to construct with an invalid amount, so no code path anywhere in the
    system -- including a future HTTP API deserializing a request body --
    can end up holding one."""
    with pytest.raises(ValidationError):
        ProposedTransaction(merchant_id="m1", amount=amount, category="electronics")


@pytest.mark.parametrize("amount", D5_INVALID_AMOUNTS, ids=D5_INVALID_AMOUNT_IDS)
def test_D5_evaluate_denies_non_finite_or_non_positive_amount(amount):
    """Defence-in-depth layer 2: evaluate() must not trust that every
    ProposedTransaction it's handed went through normal Pydantic
    validation -- buyer_agent.py and simulate.py construct these directly
    in Python, and a caller can always reach for model_construct() to
    skip validation outright (used here deliberately, to prove this
    layer catches what the schema layer might not see). An invalid
    amount must DENY with failed_check="invalid_amount", not fall through
    to check e. (amount cap) or check g. (human review threshold), both
    of which a non-finite or non-positive number can satisfy by
    accident."""
    mandate = _signed_ap2_mandate("d5-invalid-amount", max_amount=1000.0)
    tx = ProposedTransaction.model_construct(
        merchant_id="m1", amount=amount, category="electronics"
    )

    result = evaluate(mandate, tx, set())

    assert result.outcome == Outcome.DENY
    assert result.failed_check == "invalid_amount"


def test_verify_chain_reports_corruption_instead_of_crashing(tmp_path):
    """append_entry() does a single f.write() that is not guaranteed
    atomic -- a process killed mid-write (a real possibility for a
    long-running gateway) can leave a truncated, invalid-JSON final line
    in the log. A tamper-evident log used to reconstruct disputes must not
    raise an unhandled exception just because its last entry is partially
    written; it should report the corruption the same way it reports a
    broken hash chain, via (False, reason)."""
    log_path = tmp_path / "audit_log.jsonl"
    append_entry(log_path, "m1", Decision(outcome=Outcome.ALLOW, reason="ok", failed_check=None))

    with log_path.open("a", encoding="utf-8") as f:
        f.write('{"incomplete": tr')  # a write cut off mid-flush, not valid JSON

    ok, reason = verify_chain(log_path)

    assert ok is False
    assert reason is not None


def test_append_entry_recovers_from_a_prior_partial_write(tmp_path):
    """Companion to the above: after a partial-write crash, the *next*
    append_entry() call must still be able to write a new, correctly
    chained entry rather than raising -- an audit log that becomes
    permanently unwritable after one truncated line defeats its own
    purpose."""
    log_path = tmp_path / "audit_log.jsonl"
    append_entry(log_path, "m1", Decision(outcome=Outcome.ALLOW, reason="ok", failed_check=None))

    with log_path.open("a", encoding="utf-8") as f:
        f.write('{"incomplete": tr')

    # Should not raise.
    append_entry(log_path, "m2", Decision(outcome=Outcome.ALLOW, reason="ok", failed_check=None))


def test_approved_status_does_not_distinguish_execution_from_a_crash(tmp_path):
    """approval_queue.resolve() commits status='approved' *before*
    razorpay_client.create_order() is ever called (see cli.py's
    _resolve()). If the process dies between that commit and the Razorpay
    call, the row is left in 'approved' state forever -- identical to a
    row where the order really was created. There is currently no way to
    tell, from the queue alone, whether an approved request still needs to
    be executed.

    This test stands in for that crash: it resolves a request as approved
    and never calls Razorpay (exactly the state a crash right after
    resolve() would leave behind), then asserts the queue's own state
    records that execution has not happened. Today 'approved' is a
    terminal status, so it can't."""
    queue = ApprovalQueue(tmp_path / "approvals.db")
    mandate = _signed_ap2_mandate("crash-between-resolve-and-pay")
    tx = ProposedTransaction(merchant_id="m1", amount=800.0, category="electronics")
    decision = Decision(
        outcome=Outcome.NEEDS_HUMAN, reason="t", failed_check="human_review_threshold"
    )
    request_id = queue.enqueue(mandate, tx, decision, "explanation")

    queue.resolve(request_id, approved=True)  # ...and imagine the process dies right here.

    row = queue.get(request_id)
    queue.close()

    assert row["status"] != "approved", (
        "row status is 'approved' with no way to distinguish 'approved, "
        "not yet executed' from 'approved and executed' -- a crash "
        "between resolve() and the Razorpay call is unrecoverable and "
        "undetectable from queue state alone"
    )
