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

from darwaza import config, llm_explainer, observability, razorpay_client
from darwaza.approval_queue import ApprovalQueue
from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate, verify_signature
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
        decision_id: str,
        request_id: str | None = None,
        explanation: str | None = None,
    ) -> None:
        self.mandate = mandate
        self.mandate_id = mandate.mandate_id
        self.proposed_tx = proposed_tx
        self.decision = decision
        self.audit_entry = audit_entry
        self.decision_id = decision_id
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

    A `decision_id` is minted here — "at the door" — and threaded
    through the audit entry, the approval queue row (for NEEDS_HUMAN),
    and the structured log line this call emits (see observability.py).
    """
    decision_id = observability.new_decision_id()

    # Timed separately from the evaluate() call below (a second,
    # harmless call — verify_signature() is pure/side-effect-free)
    # because it's the one check in evaluate() with real computational
    # cost (Ed25519 crypto) worth measuring on its own; see
    # observability.py's module docstring for why the other ~7 checks
    # aren't individually instrumented.
    with observability.time_decision() as sig_timer:
        verify_signature(mandate)

    store = NonceStore(nonce_db_path)
    try:
        with observability.time_decision() as eval_timer:
            decision = evaluate(mandate, proposed_tx, store)
    finally:
        store.close()

    audit_entry = append_entry(log_path, mandate.mandate_id, decision, decision_id=decision_id)

    request_id = None
    explanation = None
    if decision.outcome == Outcome.NEEDS_HUMAN:
        explanation = llm_explainer.explain(mandate, proposed_tx, decision)
        queue = ApprovalQueue(approval_db_path)
        try:
            request_id = queue.enqueue(
                mandate, proposed_tx, decision, explanation, decision_id=decision_id
            )
        finally:
            queue.close()

    observability.log_decision(
        decision_id=decision_id,
        mandate_id=mandate.mandate_id,
        outcome=decision.outcome.value,
        failed_check=decision.failed_check,
        evaluate_duration_ms=eval_timer["duration_ms"],
        signature_verify_duration_ms=sig_timer["duration_ms"],
        request_id=request_id,
    )

    return AuthorizationResult(
        mandate,
        proposed_tx,
        decision,
        audit_entry,
        decision_id=decision_id,
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
        readable = {
            "approved_pending_execution": "approved (execution pending)",
            "executed": "approved and executed",
            "denied": "denied",
        }.get(status, status)
        super().__init__(f"Request '{request_id}' is already {readable}.")
        self.request_id = request_id
        self.status = status


class ApprovalNotYetApprovedError(ValueError):
    """execute_approval() was called on a request that isn't in
    'approved_pending_execution' state — either no human has approved it
    yet ('pending'), or it was denied. Executing a payment for either of
    those would bypass the human decision this whole queue exists to
    enforce, so this is refused rather than attempted. A request already
    'executed' is handled separately, idempotently (see
    execute_approval()) — it isn't an error, just a no-op."""

    def __init__(self, request_id: str, status: str) -> None:
        super().__init__(
            f"Request '{request_id}' is '{status}', not approved-and-pending-execution — "
            "nothing to execute."
        )
        self.request_id = request_id
        self.status = status


class ResolutionResult:
    """Everything a caller needs to report a human's approve/deny
    decision: the audit entry it produced, and — only when approved —
    whatever the immediate Razorpay execution attempt returned, or why
    it didn't succeed. Exactly one of razorpay_order/razorpay_error is
    set when approved=True; both are None when approved=False (a denial
    never attempts to create an order).

    `status` reflects the approval queue row's status right after this
    call: 'denied' when approved=False; 'executed' when the immediate
    Razorpay attempt succeeded; 'approved_pending_execution' when it
    didn't (see DECISIONS.md's Stage 6 entry) — in which case
    `service.execute_approval(request_id)` is how it gets retried,
    without repeating the human decision or re-claiming the mandate's
    nonce."""

    def __init__(
        self,
        request_id: str,
        mandate: NormalizedMandate,
        proposed_tx: ProposedTransaction,
        decision: Decision,
        audit_entry: dict,
        *,
        decision_id: str,
        approved: bool,
        status: str,
        razorpay_order: dict | None = None,
        razorpay_error: str | None = None,
    ) -> None:
        self.request_id = request_id
        self.mandate = mandate
        self.proposed_tx = proposed_tx
        self.decision = decision
        self.audit_entry = audit_entry
        self.decision_id = decision_id
        self.approved = approved
        self.status = status
        self.razorpay_order = razorpay_order
        self.razorpay_error = razorpay_error


class ExecutionResult:
    """What `execute_approval()` (a retry of the Razorpay step for a
    request already approved, see below) hands back — the same
    razorpay_order/razorpay_error shape ResolutionResult uses for its
    own execution attempt, since it's the identical underlying
    operation."""

    def __init__(
        self,
        request_id: str,
        mandate_id: str,
        *,
        executed: bool,
        razorpay_order: dict | None = None,
        razorpay_error: str | None = None,
    ) -> None:
        self.request_id = request_id
        self.mandate_id = mandate_id
        self.executed = executed
        self.razorpay_order = razorpay_order
        self.razorpay_error = razorpay_error


def _attempt_execution(
    queue: ApprovalQueue,
    request_id: str,
    mandate: NormalizedMandate,
    proposed_tx: ProposedTransaction,
) -> tuple[dict | None, str | None]:
    """One attempt at the Razorpay side of an already-human-approved
    request, plus the matching queue bookkeeping — shared between
    resolve_approval()'s immediate attempt (right after a human
    approves) and execute_approval()'s later retry, since the Razorpay
    call and what to do with its outcome are identical in both cases;
    only what happens *before* this call (approving vs. checking an
    already-approved row's status) differs.

    The receipt is derived from `request_id`, not `mandate_id` — see
    DECISIONS.md #15's decision_id/request_id distinction, applied here:
    `request_id` is what's minted once per approval request and stays
    fixed across however many times execution is retried, which is
    exactly the stability an idempotency key needs (razorpay_client.py's
    own retry loop then reuses this same receipt across ITS internal
    attempts too).

    razorpay_client.create_order() already retries transient failures
    internally with its own bounded backoff — what reaches this function
    as an exception is either a config problem (no keys) or every
    internal retry having been exhausted. Either way this is a caught,
    expected outcome: the request stays 'approved_pending_execution'
    (record_execution_failure() never changes status) rather than being
    lost or silently marked done.
    """
    try:
        order = razorpay_client.create_order(proposed_tx.amount, receipt=f"darwaza-{request_id}")
    except RuntimeError as exc:
        queue.record_execution_failure(request_id, error=str(exc))
        return None, str(exc)
    queue.mark_executed(request_id, razorpay_order_id=order["id"])
    return order, None


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

    A fresh `decision_id` is minted for this call — a human's
    approve/deny is its own decision event, not a continuation of the
    original NEEDS_HUMAN one (see DECISIONS.md #7: the audit trail is
    two independently-chained entries, not one edited in place). The
    two decision_ids are correlated via `request_id`/`mandate_id` in
    the structured logs and the approval queue row, not merged into one.
    """
    decision_id = observability.new_decision_id()

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
    audit_entry = append_entry(log_path, mandate.mandate_id, human_decision, decision_id=decision_id)

    razorpay_order = None
    razorpay_error = None
    status = "denied"
    if approved:
        # No nonce re-claim here: this mandate was already claimed
        # inside authorize() when evaluate() first produced NEEDS_HUMAN
        # for it — a pending request in this queue is, by construction,
        # already reserved (see DECISIONS.md, D4 and Stage 3).
        queue = ApprovalQueue(approval_db_path)
        try:
            razorpay_order, razorpay_error = _attempt_execution(
                queue, request_id, mandate, proposed_tx
            )
        finally:
            queue.close()
        status = "executed" if razorpay_order is not None else "approved_pending_execution"

    observability.log_resolution(
        decision_id=decision_id,
        request_id=request_id,
        mandate_id=mandate.mandate_id,
        outcome=human_decision.outcome.value,
        approved=approved,
        razorpay_order_id=razorpay_order.get("id") if razorpay_order else None,
        razorpay_error=razorpay_error,
    )

    return ResolutionResult(
        request_id,
        mandate,
        proposed_tx,
        human_decision,
        audit_entry,
        decision_id=decision_id,
        approved=approved,
        status=status,
        razorpay_order=razorpay_order,
        razorpay_error=razorpay_error,
    )


def list_pending_execution(
    *, approval_db_path: Path = DEFAULT_APPROVAL_DB_PATH
) -> list[dict]:
    """Requests a human already approved that haven't successfully
    reached Razorpay yet — see approval_queue.ApprovalQueue.
    list_pending_execution(). Same "one implementation, not one per
    caller" reasoning as list_pending_approvals()."""
    queue = ApprovalQueue(approval_db_path)
    try:
        return queue.list_pending_execution()
    finally:
        queue.close()


def execute_approval(
    request_id: str,
    *,
    approval_db_path: Path = DEFAULT_APPROVAL_DB_PATH,
) -> ExecutionResult:
    """Retry the Razorpay execution step for a request a human already
    approved. This is the recovery path for exactly the crash
    tests/test_defect_hunt.py names: a process that died between
    approval_queue.resolve() committing and razorpay_client.create_
    order() succeeding used to leave that request permanently
    indistinguishable from one that really was executed. As of Stage 6
    it's left in 'approved_pending_execution' instead — visible via
    list_pending_execution() — and retryable here, as many times as it
    takes, without ever repeating the human approval step or re-claiming
    the mandate's nonce (that happened once, inside the original
    authorize() call, and stays claimed regardless of how many times
    execution itself is retried).

    Idempotent for the common case: a request already 'executed' returns
    its already-stored order rather than calling Razorpay again — an
    operator (or a retry job) can call this repeatedly without knowing
    in advance whether a prior call already succeeded. The deeper
    guarantee, for the rarer case of two overlapping retries actually
    racing each other, is razorpay_client.create_order()'s own
    idempotency-by-receipt lookup (see that module) plus
    ApprovalQueue.mark_executed()'s atomic, status-guarded UPDATE — at
    most one of two racing callers' mark_executed() calls can succeed,
    which is what actually prevents a double "executed" transition, not
    this early-return alone.

    Raises `ApprovalNotFoundError` if no such request exists, or
    `ApprovalNotYetApprovedError` if it's 'pending' (no human decision
    yet) or 'denied' — executing either would bypass the human decision
    this queue exists to enforce.
    """
    queue = ApprovalQueue(approval_db_path)
    try:
        row = queue.get(request_id)
        if row is None:
            raise ApprovalNotFoundError(request_id)

        if row["status"] == "executed":
            return ExecutionResult(
                request_id,
                row["mandate_id"],
                executed=True,
                razorpay_order={"id": row["razorpay_order_id"]},
            )

        if row["status"] != "approved_pending_execution":
            raise ApprovalNotYetApprovedError(request_id, row["status"])

        mandate = NormalizedMandate.model_validate_json(row["mandate_json"])
        proposed_tx = ProposedTransaction.model_validate_json(row["proposed_tx_json"])

        razorpay_order, razorpay_error = _attempt_execution(queue, request_id, mandate, proposed_tx)
    finally:
        queue.close()

    observability.log_execution(
        request_id=request_id,
        mandate_id=mandate.mandate_id,
        executed=razorpay_order is not None,
        razorpay_order_id=razorpay_order.get("id") if razorpay_order else None,
        razorpay_error=razorpay_error,
    )

    return ExecutionResult(
        request_id,
        mandate.mandate_id,
        executed=razorpay_order is not None,
        razorpay_order=razorpay_order,
        razorpay_error=razorpay_error,
    )
