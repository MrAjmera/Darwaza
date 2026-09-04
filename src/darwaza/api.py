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

Run it with:
    uvicorn darwaza.api:app --reload
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from darwaza import service
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
#   rate limited   -> 429 with Retry-After — NOT implemented yet. This
#                     endpoint has no rate limiter in front of it as of
#                     Stage 4; rate_limit.py (Stage 5) adds one, keyed
#                     per-agent/per-mandate rather than per-IP. Named
#                     here, not faked with a hardcoded 429 that never
#                     fires under real load.
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
) -> JSONResponse:
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
    """Counters derived directly from the audit log — every decision
    this process has ever made is already durably recorded there, so
    this is real data, not a placeholder, even though it's not what
    Stage 5's observability.py will eventually provide.

    What this deliberately is NOT: per-request timing, a decision_id
    breakdown, or anything resembling Prometheus's text exposition
    format. Stage 5 adds structured, per-check-timed observability with
    counters broken down by failed_check, threaded through a minted
    decision_id — a genuinely different, richer thing than "read the
    audit log and count outcomes." This endpoint exists now so
    `GET /metrics` is a real, working URL from Stage 4 on; what it
    returns gets more detailed later, not what it means.
    """
    counts = {"ALLOW": 0, "DENY": 0, "NEEDS_HUMAN": 0}
    failed_checks: dict[str, int] = {}
    total_entries = 0

    if log_path.exists():
        with log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total_entries += 1
                outcome = entry.get("outcome")
                if outcome in counts:
                    counts[outcome] += 1
                failed_check = entry.get("failed_check")
                if failed_check:
                    failed_checks[failed_check] = failed_checks.get(failed_check, 0) + 1

    chain_ok, chain_break_reason = verify_chain(log_path)

    return {
        "audit_log_entries": total_entries,
        "outcomes": counts,
        "failed_checks": failed_checks,
        "audit_chain_intact": chain_ok,
        "audit_chain_break_reason": chain_break_reason,
    }
