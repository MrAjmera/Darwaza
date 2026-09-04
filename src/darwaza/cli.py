"""Command-line entrypoint.

  python -m darwaza.cli decide <mandate.json> <proposed_tx.json>
  python -m darwaza.cli simulate <happy-path|poisoned-catalog|needs-human>
  python -m darwaza.cli review
  python -m darwaza.cli approve <request_id>
  python -m darwaza.cli deny <request_id>

Pure presentation: every actual decision, claim, log write, explanation,
and enqueue happens in service.authorize() (see service.py and
DECISIONS.md, Stage 4) — this module's job is loading input, printing
output, and letting a human resolve pending approvals. The old
_SEEN_NONCES module-level NonceStore, and the two near-identical copies
of "evaluate -> log -> explain -> enqueue" that used to live in decide()
and simulate(), are gone: both now just call service.authorize() and
print whatever comes back.
"""

from __future__ import annotations

import json
import sys

from darwaza import service
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction
from darwaza.service import AuthorizationResult
from darwaza.simulate import SCENARIOS

# Re-exported for anyone importing these from cli.py's old location
# (env-var-overridable state file paths; see service.py for where they
# actually live now and DECISIONS.md for why they moved).
DEFAULT_LOG_PATH = service.DEFAULT_LOG_PATH
DEFAULT_NONCE_DB_PATH = service.DEFAULT_NONCE_DB_PATH
DEFAULT_APPROVAL_DB_PATH = service.DEFAULT_APPROVAL_DB_PATH


def _load(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _print_decision(mandate_id: str, decision: Decision) -> None:
    print(f"Mandate:   {mandate_id}")
    print(f"Outcome:   {decision.outcome.value}")
    print(f"Reason:    {decision.reason}")
    print(f"Failed on: {decision.failed_check or '-'}")


def _print_authorization_result(result: AuthorizationResult) -> None:
    """Shared print tail for both `decide` and `simulate` — the one place
    this CLI turns an AuthorizationResult into terminal output. Whatever
    service.authorize() actually did (claim the nonce, write the audit
    entry, and — only for NEEDS_HUMAN — explain and enqueue) already
    happened before this is called; this function does not decide
    anything or touch any store."""
    _print_decision(result.mandate_id, result.decision)

    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")
    print(f"  chained to prior entry: {result.audit_entry['prev_hash'][:12]}...")

    if result.decision.outcome == Outcome.NEEDS_HUMAN:
        print(f"\nFlagged for human review — request id: {result.request_id}")
        print(f"Explanation: {result.explanation}")
        print(f"Resolve with: python -m darwaza.cli approve {result.request_id}")
        print(f"          or: python -m darwaza.cli deny {result.request_id}")


def decide(mandate_path: str, tx_path: str) -> None:
    mandate = NormalizedMandate.model_validate(_load(mandate_path))
    proposed_tx = ProposedTransaction.model_validate(_load(tx_path))

    result = service.authorize(mandate, proposed_tx)

    _print_authorization_result(result)


def simulate(scenario_name: str) -> None:
    if scenario_name not in SCENARIOS:
        print(f"Unknown scenario '{scenario_name}'. Known: {', '.join(SCENARIOS)}")
        sys.exit(1)

    scenario_fn = SCENARIOS[scenario_name]
    result = scenario_fn(
        log_path=DEFAULT_LOG_PATH,
        nonce_db_path=DEFAULT_NONCE_DB_PATH,
        approval_db_path=DEFAULT_APPROVAL_DB_PATH,
    )

    print(f"Scenario:  {scenario_name}")
    _print_authorization_result(result)


def review() -> None:
    pending = service.list_pending_approvals()

    if not pending:
        print("No pending approvals.")
        return

    for row in pending:
        print(f"[{row['id']}] mandate={row['mandate_id']}  created={row['created_at']}")
        print(f"    reason:      {row['reason']}")
        print(f"    explanation: {row['explanation']}")
        print()


def _resolve(request_id: str, *, approved: bool) -> None:
    try:
        result = service.resolve_approval(request_id, approved=approved)
    except service.ApprovalNotFoundError as exc:
        print(str(exc))
        sys.exit(1)
    except service.ApprovalAlreadyResolvedError as exc:
        print(str(exc))
        sys.exit(1)

    verb = "APPROVED" if result.approved else "DENIED"
    print(f"Request {request_id}: {verb}")
    print(
        f"Audit log entry written to {DEFAULT_LOG_PATH} "
        f"(chained to {result.audit_entry['prev_hash'][:12]}...)"
    )

    if result.approved:
        if result.razorpay_order is not None:
            order_id = result.razorpay_order.get("id", result.razorpay_order)
            print(f"Razorpay test-mode order created: {order_id}")
        else:
            print(f"(Razorpay order not created: {result.razorpay_error})")


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
