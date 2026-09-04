"""The one place "evaluate -> claim -> log -> (explain -> enqueue)" is
written down. Both entry points — cli.py (a human at a terminal) and
api.py (a buying agent over HTTP) — call `authorize()` and do nothing
else with the policy engine, the nonce store, the audit log, the
explainer, or the approval queue directly. That used to not be true:
`cli.decide()` and `cli.simulate()` each carried their own
near-identical copy of this tail, and `simulate()`'s copy carried a
comment apologising for the duplication it was about to cause. Business
logic living twice in a presentation module (the CLI) was the actual
problem, not any specific bug in either copy.

Splitting it out here means api.py (Stage 4) gets the exact same
enforcement path the CLI has always used, by construction — there is no
second implementation of "what does an authorization request actually
go through" for the HTTP surface to drift from.
"""

from __future__ import annotations

from pathlib import Path

from darwaza import config, llm_explainer, razorpay_client
from darwaza.approval_queue import ApprovalQueue
from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import Decision, NormalizedMandate, Outcome, ProposedTransaction

# State file paths now live in config.py (Stage 5) — every module reads
# its configuration from there, not from os.environ directly. Kept as
# re-exports here (rather than deleted) since cli.py and api.py already
# reference service.DEFAULT_* and there's no reason to force a second
# rename on top of the one this stage already requires elsewhere.
DEFAULT_LOG_PATH = config.AUDIT_LOG_PATH
DEFAULT_NONCE_DB_PATH = config.NONCE_DB_PATH
DEFAULT_APPROVAL_DB_PATH = config.APPROVAL_DB_PATH


class AuthorizationResult:
    """Everything a caller (the CLI's print statements, or api.py's JSON
    response) needs to report what `authorize()` did, without any of
    them reaching back into the nonce store, audit log, or approval
    queue themselves.
    """

    def __init__(
        self,
        mandate: NormalizedMandate,
        proposed_tx: ProposedTransaction,
        decision: Decision,
        audit_entry: dict,
        *,
        request_id: str | None = None,
        explanation: str | None = None,
    ) -> None:
        self.mandate = mandate
        self.mandate_id = mandate.mandate_id
        self.proposed_tx = proposed_tx
        self.decision = decision
        self.audit_entry = audit_entry
        # Only set when decision.outcome is NEEDS_HUMAN — see authorize().
        self.request_id = request_id
        self.explanation = explanation


def authorize(
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
    *,
    log_path: Path = DEFAULT_LOG_PATH,
    nonce_db_path: Path = DEFAULT_NONCE_DB_PATH,
    approval_db_path: Path = DEFAULT_APPROVAL_DB_PATH,
) -> AuthorizationResult:
    """Run one mandate through the full authorization path: evaluate the
    rules (which, as of Stage 3, atomically claims the nonce as its own
    last step — see policy_engine.py and DECISIONS.md), write the audit
    log entry unconditionally, and — only for NEEDS_HUMAN — get a
    plain-language explanation and enqueue it for a human to resolve via
    `review`/`approve`/`deny` (CLI) or the equivalent HTTP endpoints
    (api.py).

    This is the single implementation both entry points call — see the
    module docstring for why that matters. Neither cli.py nor api.py
    should construct a NonceStore, ApprovalQueue, or call evaluate()/
    append_entry()/llm_explainer.explain() directly; if a caller finds
    itself doing that, the logic belongs here instead.
    """
    store = NonceStore(nonce_db_path)
    try:
        decision = evaluate(mandate, proposed_tx, store)
    finally:
        store.close()

    audit_entry = append_entry(log_path, mandate.mandate_id, decision)

    request_id = None
    explanation = None
    if decision.outcome == Outcome.NEEDS_HUMAN:
        explanation = llm_explainer.explain(mandate, proposed_tx, decision)
        queue = ApprovalQueue(approval_db_path)
        try:
            request_id = queue.enqueue(mandate, proposed_tx, decision, explanation)
        finally:
            queue.close()

    return AuthorizationResult(
        mandate,
        proposed_tx,
        decision,
        audit_entry,
        request_id=request_id,
        explanation=explanation,
    )


def list_pending_approvals(
    *, approval_db_path: Path = DEFAULT_APPROVAL_DB_PATH
) -> list[dict]:
    """The pending-approvals list both `cli.review()` and api.py's
    `GET /v1/approvals` show. Trivial today, but kept here rather than
    letting either caller open an ApprovalQueue directly, for the same
    reason as authorize() — one implementation of "what does the queue
    look like," not two that can drift.
    """
    queue = ApprovalQueue(approval_db_path)
    try:
        return queue.list_pending()
    finally:
        queue.close()


class ApprovalNotFoundError(LookupError):
    """No approval request exists with this id."""

    def __init__(self, request_id: str) -> None:
        super().__init__(f"No approval request with id '{request_id}'.")
        self.request_id = request_id


class ApprovalAlreadyResolvedError(ValueError):
    """The request exists but isn't pending any more."""

    def __init__(self, request_id: str, status: str) -> None:
        super().__init__(f"Request '{request_id}' is already {status}.")
        self.request_id = request_id
        self.status = status


class ResolutionResult:
    """Everything a caller needs to report a human's approve/deny
    decision: the audit entry it produced, and — only when approved —
    whatever razorpay_client.create_order() returned, or why it didn't
    run. Exactly one of razorpay_order/razorpay_error is set when
    approved=True; both are None when approved=False (a denial never
    attempts to create an order)."""

    def __init__(
        self,
        request_id: str,
        mandate: NormalizedMandate,
        proposed_tx: ProposedTransaction,
        decision: Decision,
        audit_entry: dict,
        *,
        approved: bool,
        razorpay_order: dict | None = None,
        razorpay_error: str | None = None,
    ) -> None:
        self.request_id = request_id
        self.mandate = mandate
        self.proposed_tx = proposed_tx
        self.decision = decision
        self.audit_entry = audit_entry
        self.approved = approved
        self.razorpay_order = razorpay_order
        self.razorpay_error = razorpay_error


def resolve_approval(
    request_id: str,
    *,
    approved: bool,
    log_path: Path = DEFAULT_LOG_PATH,
    approval_db_path: Path = DEFAULT_APPROVAL_DB_PATH,
) -> ResolutionResult:
    """Record a human's decision on a pending NEEDS_HUMAN request:
    resolve it in the approval queue, write a second, independently
    hash-chained audit log entry for the human's decision (see
    DECISIONS.md #7 for why this is a new entry, not an edit to the
    first), and — only on approval — attempt to create the Razorpay
    test-mode order.

    Raises `ApprovalNotFoundError` or `ApprovalAlreadyResolvedError` for
    the two ways `request_id` can be invalid, rather than printing and
    exiting itself — this is business logic shared by cli.py (which
    turns those into a printed message and exit code) and api.py (which
    turns them into 404/409 responses); which presentation happens is
    not this function's decision to make.
    """
    queue = ApprovalQueue(approval_db_path)
    try:
        row = queue.get(request_id)
        if row is None:
            raise ApprovalNotFoundError(request_id)
        if row["status"] != "pending":
            raise ApprovalAlreadyResolvedError(request_id, row["status"])
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
    audit_entry = append_entry(log_path, mandate.mandate_id, human_decision)

    razorpay_order = None
    razorpay_error = None
    if approved:
        # No nonce re-claim here: this mandate was already claimed
        # inside authorize() when evaluate() first produced NEEDS_HUMAN
        # for it — a pending request in this queue is, by construction,
        # already reserved (see DECISIONS.md, D4 and Stage 3).
        try:
            razorpay_order = razorpay_client.create_order(
                proposed_tx.amount, receipt=f"darwaza-{mandate.mandate_id}"
            )
        except RuntimeError as exc:
            razorpay_error = str(exc)

    return ResolutionResult(
        request_id,
        mandate,
        proposed_tx,
        human_decision,
        audit_entry,
        approved=approved,
        razorpay_order=razorpay_order,
        razorpay_error=razorpay_error,
    )
