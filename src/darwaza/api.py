"""HTTP entry point for buying agents. See DECISIONS.md #13 for why this
exists alongside cli.py rather than replacing it: agents are machines on
a network and need a network interface; a human resolving a NEEDS_HUMAN
request with `approve`/`deny` is a person making a judgment call at a
terminal, which the CLI stays the right interface for.

Every endpoint here is a thin adapter over service.py — this module
parses HTTP in, calls exactly one service.py function, and turns the
result (or a typed exception) into an HTTP response. No policy check,
nonce claim, audit write, explanation, or queue operation happens in
this file; if you find yourself reaching for NonceStore, ApprovalQueue,
or evaluate() directly here, that logic belongs in service.py instead.

State file paths are injected via FastAPI dependencies
(`_log_path`/`_nonce_db_path`/`_approval_db_path`) rather than read as
service.py module constants directly in each handler. In a real
deployment these always resolve to the same env-var-configured paths
service.py defaults to — this indirection exists so tests
(tests/test_api.py) can point a single running `app` at an isolated
temp directory via `app.dependency_overrides`, without depending on
which test module happens to import darwaza.service first (module-level
constants computed once at import time, like these, are exactly the
kind of thing import order can make fragile to override any other way).
The rate limiter (`_rate_limiter`, see rate_limit.py) is injected the
same way and for the same reason — tests override it with a
tiny-capacity instance to exercise 429 without waiting on real time.

Run it with:
    uvicorn darwaza.api:app --reload
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from darwaza import observability, rate_limit, service
from darwaza.audit_log import verify_chain
from darwaza.schema import NormalizedMandate, Outcome, ProposedTransaction

app = FastAPI(
    title="Darwaza",
    description=(
        "Merchant-side authorization gateway for AI buying agents. "
        "See DECISIONS.md in the repo for the reasoning behind every "
        "check and status code below."
    ),
)


# ---------------------------------------------------------------------------
# Path dependencies — see module docstring for why these exist instead of
# reading service.DEFAULT_* directly in each handler.
# ---------------------------------------------------------------------------


def _log_path() -> Path:
    return service.DEFAULT_LOG_PATH


def _nonce_db_path() -> Path:
    return service.DEFAULT_NONCE_DB_PATH


def _approval_db_path() -> Path:
    return service.DEFAULT_APPROVAL_DB_PATH


# Default: 10-request burst, refilling at 10/hour thereafter. Generous
# for a human-paced flow (DECISIONS.md's "three purchases an hour")
# while a tight loop exhausts its burst in well under a second and is
# then throttled to roughly one request every six minutes. One shared,
# process-wide instance — same lifetime as observability.COUNTERS, and
# for the same reason: this is per-process rate limiting, not
# coordinated across instances (see DECISIONS.md's multi-instance open
# item, which applies here too).
_AUTHORIZE_RATE_LIMITER = rate_limit.RateLimiter(capacity=10, refill_rate_per_second=10 / 3600)


def _rate_limiter() -> rate_limit.RateLimiter:
    return _AUTHORIZE_RATE_LIMITER


# ---------------------------------------------------------------------------
# Request/response shapes
# ---------------------------------------------------------------------------


class AuthorizeRequest(BaseModel):
    """A buying agent's request: the mandate it's acting under, and the
    specific transaction it wants to execute against it. Both are
    required in the body — there is no endpoint that accepts a mandate
    without a proposed transaction, because "is this mandate valid" and
    "is this specific transaction authorized by it" are never separable
    questions here (see policy_engine.evaluate())."""

    mandate: NormalizedMandate
    proposed_tx: ProposedTransaction


def _decision_body(result: service.AuthorizationResult) -> dict:
    body = {
        "mandate_id": result.mandate_id,
        "outcome": result.decision.outcome.value,
        "reason": result.decision.reason,
        "failed_check": result.decision.failed_check,
    }
    if result.decision.outcome == Outcome.NEEDS_HUMAN:
        body["request_id"] = result.request_id
        body["explanation"] = result.explanation
    return body


# ---------------------------------------------------------------------------
# POST /v1/authorize
# ---------------------------------------------------------------------------
#
# Status codes, deliberately:
#   ALLOW          -> 200
#   DENY           -> 403, with failed_check in the body
#   NEEDS_HUMAN    -> 202 Accepted, with request_id and a Location header
#   malformed body -> 400 (see the RequestValidationError handler below —
#                     FastAPI's default is 422; this project's spec calls
#                     for 400, so that default is overridden)
#   rate limited   -> 429 with Retry-After, from rate_limit.py (Stage 5),
#                     keyed per-agent/per-mandate rather than per-IP —
#                     see rate_limit.py's module docstring and
#                     DECISIONS.md for why.
#
# 202 is used on purpose for NEEDS_HUMAN: "accepted for processing, not
# complete" is exactly what NEEDS_HUMAN means — the request was
# understood and something is now in motion (a queued approval), but no
# final ALLOW/DENY exists yet.


@app.post("/v1/authorize")
def authorize(
    payload: AuthorizeRequest,
    log_path: Path = Depends(_log_path),
    nonce_db_path: Path = Depends(_nonce_db_path),
    approval_db_path: Path = Depends(_approval_db_path),
    limiter: rate_limit.RateLimiter = Depends(_rate_limiter),
) -> JSONResponse:
    # Rate limiting runs before evaluate() and is NOT a policy DENY —
    # "we didn't evaluate this one, try again shortly" is a different
    # claim than "we evaluated this and rejected it," which is exactly
    # why it's a distinct status code (429, not 403) and doesn't touch
    # the nonce store, audit log, or counters at all.
    agent_key = payload.mandate.agent_id or payload.mandate.principal_id
    allowed, retry_after = limiter.allow(agent_key, payload.mandate.mandate_id)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limited",
                "detail": "Too many authorize requests for this agent/mandate.",
            },
            headers={"Retry-After": str(max(1, round(retry_after)))},
        )

    result = service.authorize(
        payload.mandate,
        payload.proposed_tx,
        log_path=log_path,
        nonce_db_path=nonce_db_path,
        approval_db_path=approval_db_path,
    )
    body = _decision_body(result)

    if result.decision.outcome == Outcome.ALLOW:
        return JSONResponse(status_code=200, content=body)

    if result.decision.outcome == Outcome.DENY:
        return JSONResponse(status_code=403, content=body)

    # NEEDS_HUMAN
    return JSONResponse(
        status_code=202,
        content=body,
        headers={"Location": f"/v1/approvals/{result.request_id}"},
    )


@app.exception_handler(RequestValidationError)
def _malformed_request_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """A mandate/transaction that doesn't even parse (missing fields,
    wrong types, an amount that fails ProposedTransaction's gt=0 /
    allow_inf_nan=False constraint — see DECISIONS.md #8) is a malformed
    request, not a policy DENY: it never reached evaluate() at all. This
    project's spec calls for 400 here; FastAPI's default for a
    Pydantic-model body validation failure is 422, so that default is
    overridden for exactly this error type — nothing else in this API
    is affected."""
    return JSONResponse(
        status_code=400,
        content={"error": "malformed_request", "detail": exc.errors()},
    )


# ---------------------------------------------------------------------------
# GET /v1/approvals, POST /v1/approvals/{id}/approve|deny
# ---------------------------------------------------------------------------


@app.get("/v1/approvals")
def list_approvals(approval_db_path: Path = Depends(_approval_db_path)) -> list[dict]:
    return service.list_pending_approvals(approval_db_path=approval_db_path)


@app.get("/v1/approvals/pending-execution")
def list_pending_execution(approval_db_path: Path = Depends(_approval_db_path)) -> list[dict]:
    """Requests a human already approved (POST .../approve) that haven't
    successfully reached Razorpay yet — see DECISIONS.md's Stage 6 entry
    and approval_queue.py. A distinct list from GET /v1/approvals, which
    is only requests still waiting on a human decision in the first
    place; these two states are never the same row at the same time."""
    return service.list_pending_execution(approval_db_path=approval_db_path)


def _resolve(
    request_id: str,
    *,
    approved: bool,
    log_path: Path,
    approval_db_path: Path,
) -> JSONResponse:
    try:
        result = service.resolve_approval(
            request_id, approved=approved, log_path=log_path, approval_db_path=approval_db_path
        )
    except service.ApprovalNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": str(exc)})
    except service.ApprovalAlreadyResolvedError as exc:
        return JSONResponse(status_code=409, content={"error": "already_resolved", "detail": str(exc)})

    body = {
        "request_id": result.request_id,
        "mandate_id": result.mandate.mandate_id,
        "outcome": result.decision.outcome.value,
        "reason": result.decision.reason,
    }
    if result.approved:
        body["razorpay_order"] = result.razorpay_order
        body["razorpay_error"] = result.razorpay_error
    return JSONResponse(status_code=200, content=body)


@app.post("/v1/approvals/{request_id}/approve")
def approve_request(
    request_id: str,
    log_path: Path = Depends(_log_path),
    approval_db_path: Path = Depends(_approval_db_path),
) -> JSONResponse:
    return _resolve(request_id, approved=True, log_path=log_path, approval_db_path=approval_db_path)


@app.post("/v1/approvals/{request_id}/deny")
def deny_request(
    request_id: str,
    log_path: Path = Depends(_log_path),
    approval_db_path: Path = Depends(_approval_db_path),
) -> JSONResponse:
    return _resolve(request_id, approved=False, log_path=log_path, approval_db_path=approval_db_path)


@app.post("/v1/approvals/{request_id}/execute")
def execute_request(
    request_id: str,
    approval_db_path: Path = Depends(_approval_db_path),
) -> JSONResponse:
    """Retry the Razorpay execution step for a request already approved
    — see service.execute_approval() and DECISIONS.md's Stage 6 entry.
    404 (unknown id) and 409 (never approved, or denied) mirror
    approve/deny's own error mapping; a request that's already
    'executed' is not an error here — it returns 200 with the
    already-stored order (idempotent), same as a fresh success."""
    try:
        result = service.execute_approval(request_id, approval_db_path=approval_db_path)
    except service.ApprovalNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": "not_found", "detail": str(exc)})
    except service.ApprovalNotYetApprovedError as exc:
        return JSONResponse(
            status_code=409, content={"error": "not_approved_pending_execution", "detail": str(exc)}
        )

    return JSONResponse(
        status_code=200,
        content={
            "request_id": result.request_id,
            "mandate_id": result.mandate_id,
            "executed": result.executed,
            "razorpay_order": result.razorpay_order,
            "razorpay_error": result.razorpay_error,
        },
    )


# ---------------------------------------------------------------------------
# GET /healthz, GET /metrics
# ---------------------------------------------------------------------------


@app.get("/healthz")
def healthz() -> dict:
    """Liveness only — does this process respond at all. Does not check
    the audit chain or database files; a slow/corrupt log shouldn't make
    a load balancer think the process is down when it's still serving
    requests correctly for everything except that one file."""
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/metrics")
def metrics(log_path: Path = Depends(_log_path)) -> dict:
    """Two different kinds of number, clearly labeled as such rather
    than merged into one undifferentiated blob:

    - `counters`: ALLOW/DENY/NEEDS_HUMAN broken down by failed_check,
      from observability.COUNTERS — in-process, thread-safe, and reset
      to zero every time this process restarts. This is what a real
      metrics/dashboard consumer wants: current, per-instance activity.
    - `audit_log`: entry count and hash-chain integrity, read directly
      from the durable audit log — survives restarts, reflects this
      process's *entire* history including before it last restarted,
      and is intentionally NOT what `counters` reports (see
      observability.py's module docstring for why the audit log and
      observability counters are kept as two separate concerns with two
      separate storage strategies, not one).

    Because of that difference, `counters` and `audit_log` can
    legitimately disagree — e.g. right after a restart, `counters` reads
    all zero while `audit_log` still shows every decision this instance
    has ever recorded. That's not a bug in either number.
    """
    counters = observability.COUNTERS.snapshot()

    total_entries = 0
    if log_path.exists():
        with log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    total_entries += 1

    chain_ok, chain_break_reason = verify_chain(log_path)

    return {
        "counters": counters,
        "audit_log": {
            "entries": total_entries,
            "chain_intact": chain_ok,
            "chain_break_reason": chain_break_reason,
        },
    }
