"""Command-line entrypoint.

  python -m darwaza.cli decide <mandate.json> <proposed_tx.json>
  python -m darwaza.cli simulate <happy-path|poisoned-catalog|needs-human>
  python -m darwaza.cli review
  python -m darwaza.cli approve <request_id>
  python -m darwaza.cli deny <request_id>
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from darwaza import llm_explainer, razorpay_client
from darwaza.approval_queue import ApprovalQueue
from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction
from darwaza.simulate import SCENARIOS

# State file locations. Default to the repo root (stable regardless of
# the caller's cwd — this is a real gateway's persistent state, not
# scratch output, so it shouldn't move around based on where you happen
# to invoke the command from). Overridable via env vars so tests (and a
# user who wants a clean, isolated demo run) can point them elsewhere
# without touching the real repo-root files.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_LOG_PATH = Path(os.environ.get("DARWAZA_AUDIT_LOG_PATH", str(REPO_ROOT / "audit_log.jsonl")))
DEFAULT_NONCE_DB_PATH = Path(os.environ.get("DARWAZA_NONCE_DB_PATH", str(REPO_ROOT / "nonces.db")))
DEFAULT_APPROVAL_DB_PATH = Path(
    os.environ.get("DARWAZA_APPROVAL_DB_PATH", str(REPO_ROOT / "approvals.db"))
)

# Persistent across CLI invocations and process restarts — see
# nonce_store.py and DECISIONS.md.
_SEEN_NONCES = NonceStore(DEFAULT_NONCE_DB_PATH)


def _load(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _print_decision(mandate_id: str, decision: Decision) -> None:
    print(f"Mandate:   {mandate_id}")
    print(f"Outcome:   {decision.outcome.value}")
    print(f"Reason:    {decision.reason}")
    print(f"Failed on: {decision.failed_check or '-'}")


def _handle_result(
    mandate: NormalizedMandate, proposed_tx: ProposedTransaction, decision: Decision
) -> None:
    """Common tail for both `decide` and `simulate`: print, log, and — if
    the outcome is NEEDS_HUMAN — get an explanation and enqueue it for a
    human to resolve via `review`/`approve`/`deny`."""
    _print_decision(mandate.mandate_id, decision)

    entry = append_entry(DEFAULT_LOG_PATH, mandate.mandate_id, decision)
    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")
    print(f"  chained to prior entry: {entry['prev_hash'][:12]}...")

    if decision.outcome == Outcome.NEEDS_HUMAN:
        explanation = llm_explainer.explain(mandate, proposed_tx, decision)
        queue = ApprovalQueue(DEFAULT_APPROVAL_DB_PATH)
        try:
            request_id = queue.enqueue(mandate, proposed_tx, decision, explanation)
        finally:
            queue.close()
        print(f"\nFlagged for human review — request id: {request_id}")
        print(f"Explanation: {explanation}")
        print(f"Resolve with: python -m darwaza.cli approve {request_id}")
        print(f"          or: python -m darwaza.cli deny {request_id}")


def decide(mandate_path: str, tx_path: str) -> None:
    mandate = NormalizedMandate.model_validate(_load(mandate_path))
    proposed_tx = ProposedTransaction.model_validate(_load(tx_path))

    # evaluate() claims the nonce itself now, atomically, as its last
    # step, for both ALLOW and NEEDS_HUMAN (see DECISIONS.md, Stage 3 —
    # the old check-then-add pattern here was D1's TOCTOU race).
    decision = evaluate(mandate, proposed_tx, _SEEN_NONCES)

    _handle_result(mandate, proposed_tx, decision)


def simulate(scenario_name: str) -> None:
    if scenario_name not in SCENARIOS:
        print(f"Unknown scenario '{scenario_name}'. Known: {', '.join(SCENARIOS)}")
        sys.exit(1)

    scenario_fn = SCENARIOS[scenario_name]
    result = scenario_fn(log_path=DEFAULT_LOG_PATH, nonce_db_path=DEFAULT_NONCE_DB_PATH)

    print(f"Scenario:  {scenario_name}")
    # scenario functions already print/log via _run(); _handle_result
    # would double-log, so just handle the NEEDS_HUMAN enqueue step here.
    _print_decision(result.mandate_id, result.decision)
    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")

    if result.decision.outcome == Outcome.NEEDS_HUMAN:
        explanation = llm_explainer.explain(result.mandate, result.proposed_tx, result.decision)
        queue = ApprovalQueue(DEFAULT_APPROVAL_DB_PATH)
        try:
            request_id = queue.enqueue(result.mandate, result.proposed_tx, result.decision, explanation)
        finally:
            queue.close()
        print(f"\nFlagged for human review — request id: {request_id}")
        print(f"Explanation: {explanation}")
        print(f"Resolve with: python -m darwaza.cli approve {request_id}")
        print(f"          or: python -m darwaza.cli deny {request_id}")


def review() -> None:
    queue = ApprovalQueue(DEFAULT_APPROVAL_DB_PATH)
    try:
        pending = queue.list_pending()
    finally:
        queue.close()

    if not pending:
        print("No pending approvals.")
        return

    for row in pending:
        print(f"[{row['id']}] mandate={row['mandate_id']}  created={row['created_at']}")
        print(f"    reason:      {row['reason']}")
        print(f"    explanation: {row['explanation']}")
        print()


def _resolve(request_id: str, *, approved: bool) -> None:
    queue = ApprovalQueue(DEFAULT_APPROVAL_DB_PATH)
    try:
        row = queue.get(request_id)
        if row is None:
            print(f"No approval request with id '{request_id}'.")
            sys.exit(1)
        if row["status"] != "pending":
            print(f"Request '{request_id}' is already {row['status']}.")
            sys.exit(1)

        queue.resolve(request_id, approved=approved)
    finally:
        queue.close()

    mandate = NormalizedMandate.model_validate_json(row["mandate_json"])
    proposed_tx = ProposedTransaction.model_validate_json(row["proposed_tx_json"])

    # The human's decision is itself recorded as a new audit log entry —
    # the audit trail for a NEEDS_HUMAN mandate is now two lines: the
    # deterministic flag, then the human resolution. This is the human
    # action DECISIONS.md's thesis is about: it's what re-anchors
    # liability for this one transaction.
    outcome = Outcome.ALLOW if approved else Outcome.DENY
    verb = "Approved" if approved else "Denied"
    human_decision = Decision(
        outcome=outcome,
        reason=f"{verb} by human review (request {request_id}). Original flag: {row['reason']}",
        failed_check=None if approved else "human_review_denied",
    )
    entry = append_entry(DEFAULT_LOG_PATH, mandate.mandate_id, human_decision)
    print(f"Request {request_id}: {verb.upper()}")
    print(f"Audit log entry written to {DEFAULT_LOG_PATH} (chained to {entry['prev_hash'][:12]}...)")

    if approved:
        # No _SEEN_NONCES.add() here: this mandate was already claimed
        # when evaluate() first produced NEEDS_HUMAN for it (see
        # decide()/simulate.py and DECISIONS.md, D4 and Stage 3) — a
        # pending request in this queue is, by construction, already
        # reserved. Re-adding here would just be re-confirming state
        # that's already true.
        try:
            order = razorpay_client.create_order(
                proposed_tx.amount, receipt=f"darwaza-{mandate.mandate_id}"
            )
            print(f"Razorpay test-mode order created: {order.get('id', order)}")
        except RuntimeError as exc:
            print(f"(Razorpay order not created: {exc})")


def approve(request_id: str) -> None:
    _resolve(request_id, approved=True)


def deny(request_id: str) -> None:
    _resolve(request_id, approved=False)


def main() -> None:
    usage = (
        "Usage:\n"
        "  python -m darwaza.cli decide <mandate.json> <proposed_tx.json>\n"
        "  python -m darwaza.cli simulate <" + "|".join(SCENARIOS) + ">\n"
        "  python -m darwaza.cli review\n"
        "  python -m darwaza.cli approve <request_id>\n"
        "  python -m darwaza.cli deny <request_id>"
    )
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    command = sys.argv[1]
    if command == "decide" and len(sys.argv) == 4:
        decide(sys.argv[2], sys.argv[3])
    elif command == "simulate" and len(sys.argv) == 3:
        simulate(sys.argv[2])
    elif command == "review" and len(sys.argv) == 2:
        review()
    elif command == "approve" and len(sys.argv) == 3:
        approve(sys.argv[2])
    elif command == "deny" and len(sys.argv) == 3:
        deny(sys.argv[2])
    else:
        print(usage)
        sys.exit(1)


if __name__ == "__main__":
    main()
