# Darwaza

A protocol-agnostic, merchant-side authorization gateway for AI buying
agents. Given a mandate (an AP2-style intent mandate or an ACP-style
scoped token) and a proposed transaction, Darwaza deterministically
decides **ALLOW / DENY / NEEDS_HUMAN**, gets human sign-off for anything
flagged, and writes a tamper-evident audit trail for every step.

> **⚠️ Demo signing keys are checked into source control on purpose.**
> `src/darwaza/keys.py` holds real Ed25519 private keys for three demo
> principals, committed to this repo, so the test suite and CLI demo
> run for anyone who clones it with no setup step. This is never
> acceptable for a real signing key — see [DECISIONS.md #3](DECISIONS.md)
> and [#18](DECISIONS.md) for why that trade-off is made explicitly here,
> and [LIMITATIONS.md](LIMITATIONS.md) for the full accounting of what
> that does and doesn't mean for this project's scope.

**Two entry points, on purpose, not one replacing the other:** a buying
agent is a machine on a network, so it talks to Darwaza over HTTP
(`api.py` — `POST /v1/authorize`, see the quickstart below). A human
resolving a flagged request is a person making a judgment call at a
terminal, which is what `cli.py`'s `review`/`approve`/`deny`/`execute`
commands are for — an HTTP API isn't a more "modern" replacement for
that, it's a different consumer with a different reason to exist (see
[DECISIONS.md #13](DECISIONS.md)). Both call into the exact same
`service.py` enforcement path; neither re-implements it.

See [DECISIONS.md](DECISIONS.md) for why it's built this way, decision
by decision; [docs/HLD.md](docs/HLD.md) for the context diagram and
trust boundary; [docs/LLD.md](docs/LLD.md) for sequence diagrams, the
full check order, and the data model; [docs/SCALING.md](docs/SCALING.md)
for what's built vs. designed-but-not-built beyond one process; and
[LIMITATIONS.md](LIMITATIONS.md) for the complete honest accounting,
including the full defect history. [docs/BUILD_LOG.md](docs/BUILD_LOG.md)
is a plain-language, step-by-step account of how the earliest stages
were built.

## What's real vs. what's scoped out

**Real:** normalized mandate schema (AP2 and ACP asymmetry preserved,
not papered over), a pure deterministic policy engine (7 checks, zero
LLM calls in the enforcement path), real Ed25519 signature verification
that is genuinely per-principal (each registered principal has their own
keypair, so a signature is checked against *that specific principal's*
key, not just "some key the system trusts" — see below), persistent
SQLite-backed replay detection, a hash-chained tamper-evident audit log,
a buyer-agent simulator with a real (not just unit-tested)
poisoned-catalog attack, an LLM explainer that is structurally unable to
influence a decision, a human approval queue whose "approved" and
"executed" are two separately-tracked states (not one that quietly means
both), and Razorpay test-mode order creation with real
retry/timeout/idempotency-by-receipt behavior so a transient failure is
retryable rather than lost.

**Explicitly out of scope**, named directly rather than hidden: key
*management* (registration, issuance, rotation, revocation — see
DECISIONS.md #18 for the precise line: verification is per-principal
now, but the registry is still a small hardcoded dict of three demo
principals, not a KMS), multi-instance coordination (the nonce store and
approval queue are each a single SQLite file), a full payment round-trip
without a frontend (Razorpay integration stops at order creation), and a
tuned risk model behind the 0.5 human-review threshold (it's a
defensible round number, not derived from data). See DECISIONS.md's
"Open items" for the complete list.

## Setup

```
cd darwaza
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

The `pip install -e .` step (using `pyproject.toml`) is what makes
`python -m darwaza.cli ...` work directly. Without it, only `pytest`
would work (it separately gets `src` on its path via `pythonpath = src`
in `pytest.ini`) — the CLI itself would raise
`ModuleNotFoundError: No module named 'darwaza'`. Re-run this any time
after pulling new changes; you don't need to repeat it otherwise, since
it's an editable install (`-e`) that just points at `src/` directly.

Optional, only if you want the live paths (both are lazily imported —
nothing else needs them):
```
pip install anthropic razorpay
# razorpay 1.4.2 still imports pkg_resources, removed in setuptools>=81
# -- if `import razorpay` fails with ModuleNotFoundError: pkg_resources,
# run: pip install "setuptools<81"  (see .github/workflows/ci.yml)
```

## Run the demo

```
# Direct decide: pass a mandate + proposed transaction straight in
python -m darwaza.cli decide tests/fixtures/ap2_mandate.json tests/fixtures/ap2_proposed_tx.json
python -m darwaza.cli decide tests/fixtures/acp_token.json tests/fixtures/acp_proposed_tx.json
python -m darwaza.cli decide tests/fixtures/expired_mandate.json tests/fixtures/expired_proposed_tx.json

# Buyer-agent scenarios: a simulated agent decides what to buy, then the
# gate evaluates its actual proposal
python -m darwaza.cli simulate happy-path        # ALLOW
python -m darwaza.cli simulate poisoned-catalog   # DENY — a poisoned product listing tries to inflate the order
python -m darwaza.cli simulate needs-human        # NEEDS_HUMAN — a legitimate but large request

# Human approval flow, for a NEEDS_HUMAN result
python -m darwaza.cli review
python -m darwaza.cli approve <request_id>   # or: deny <request_id>

# If approval succeeded but execution against Razorpay didn't (no keys
# configured, or a transient failure) -- retry just that step, as many
# times as it takes, without repeating the human decision:
python -m darwaza.cli execute <request_id>
```

Set `ANTHROPIC_API_KEY` before `simulate needs-human` to get a real LLM
explanation instead of the labeled fallback template. Set
`RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` (test-mode keys, from your
Razorpay dashboard) before `approve` to create a real Razorpay test-mode
order.

Every run appends to `audit_log.jsonl` in the repo root (gitignored —
it's runtime state, not source). `nonces.db` and `approvals.db` are the
same: gitignored, persistent, safe to delete to reset the demo.

## API quickstart

```
uvicorn darwaza.api:app --reload
```

Every example below is a real request/response pair, captured from an
actual running instance (not hand-written) — a mandate needs a real
signature to reach anything past check a0/a, so a hand-typed example
would just DENY on `signature`.

**ALLOW** — a mandate authorizing up to ₹1000 in electronics/books,
requesting ₹300:

```
$ curl -s -X POST http://127.0.0.1:8000/v1/authorize \
    -H "Content-Type: application/json" \
    -d '{"mandate": {...}, "proposed_tx": {"merchant_id": "merchant-bestbuy", "amount": 300.0, "category": "electronics"}}'

{"mandate_id":"readme-demo-allow-1","outcome":"ALLOW","reason":"All checks passed.","failed_check":null}
```
(HTTP 200.)

**NEEDS_HUMAN** — same mandate, requesting ₹800 (80% of the ₹1000 cap,
over the 50% auto-approve threshold):

```
$ curl -s -i -X POST http://127.0.0.1:8000/v1/authorize \
    -H "Content-Type: application/json" \
    -d '{"mandate": {...}, "proposed_tx": {"merchant_id": "merchant-bestbuy", "amount": 800.0, "category": "electronics"}}'

HTTP/1.1 202 Accepted
location: /v1/approvals/962a2f87-2cb6-4901-b513-0cdb338fb662

{"mandate_id":"readme-demo-needs-human-1","outcome":"NEEDS_HUMAN","reason":"Transaction amount 800.0 is 80% of mandate cap 1000.0 — above the 50% auto-approve threshold, routed to human review.","failed_check":"human_review_threshold","request_id":"962a2f87-2cb6-4901-b513-0cdb338fb662","explanation":"[LLM explanation unavailable — no ANTHROPIC_API_KEY configured] Mandate readme-demo-needs-human-1 (principal user-krishna) requests 800.0 for merchant merchant-bestbuy (electronics), against a stated cap of 1000.0. Flagged for human review because: Transaction amount 800.0 is 80% of mandate cap 1000.0 — above the 50% auto-approve threshold, routed to human review."}
```

**A human resolves it** (in a real flow, a person reads `GET
/v1/approvals` first — shown here for the same request_id above):

```
$ curl -s http://127.0.0.1:8000/v1/approvals
[{"id":"962a2f87-2cb6-4901-b513-0cdb338fb662","mandate_id":"readme-demo-needs-human-1", ...}]

$ curl -s -X POST http://127.0.0.1:8000/v1/approvals/962a2f87-2cb6-4901-b513-0cdb338fb662/approve
{"request_id":"962a2f87-2cb6-4901-b513-0cdb338fb662","mandate_id":"readme-demo-needs-human-1","outcome":"ALLOW","reason":"Approved by human review (request 962a2f87-2cb6-4901-b513-0cdb338fb662). Original flag: Transaction amount 800.0 is 80% of mandate cap 1000.0 — above the 50% auto-approve threshold, routed to human review.","razorpay_order":null,"razorpay_error":"RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. Get test-mode keys from the Razorpay dashboard (Settings -> API Keys) and set them as environment variables before executing a transaction."}
```

No Razorpay keys configured in this capture, so `razorpay_order` is
`null` and the request lands in `approved_pending_execution` (see
[DECISIONS.md #17](DECISIONS.md)) rather than pretending an order was
created — confirmed via `GET /v1/approvals/pending-execution`:

```
$ curl -s http://127.0.0.1:8000/v1/approvals/pending-execution
[{"id":"962a2f87-2cb6-4901-b513-0cdb338fb662", ..., "execution_attempts":1, "last_execution_error":"RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set...."}]
```

Retry with `POST /v1/approvals/{id}/execute` once keys are configured
(or as many times as it takes — see `docs/LLD.md`'s NEEDS_HUMAN →
approve → execute sequence diagram).

**`GET /metrics`**, after the two requests above:

```
$ curl -s http://127.0.0.1:8000/metrics
{"counters":{"by_outcome":{"ALLOW":2,"DENY":0,"NEEDS_HUMAN":1},"by_failed_check":{"human_review_threshold":1}},"audit_log":{"entries":3,"chain_intact":true,"chain_break_reason":null}}
```
`counters` is in-process (resets on restart); `audit_log` is durable
(see [DECISIONS.md #15](DECISIONS.md) for why these are two different
numbers, not one).

See `tests/test_api.py` for every endpoint and every documented status
code (200/403/202/400/404/409/429) as executable assertions, not just
prose.

## Run the tests

```
python -m pytest
```

- `test_policy_engine.py` — every check in `evaluate()`, in isolation.
- `test_attacks.py` — the same checks, framed as attacks (replay,
  expiry, cross-merchant use, cap-exceeding requests, forged/tampered
  signatures, and — via `simulate.py` — a poisoned catalog manipulating
  the buying agent).
- `test_nonce_store.py`, `test_approval_queue.py` — the two persistent
  SQLite-backed stores, including "survives a restart" as an explicit
  test case.
- `test_buyer_agent.py`, `test_simulate.py` — the simulated buying agent
  and the full agent → gate → audit-log path.
- `test_llm_explainer.py`, `test_razorpay_client.py` — the two
  optional-dependency integrations, tested against their fallback /
  fail-loudly behavior (no live API calls in the automated suite).
  `test_razorpay_client.py`'s retry/timeout/idempotency-by-receipt tests
  run against a fake `razorpay.Client` (skipped, not failing, if
  `razorpay` isn't installed at all).
- `test_service_execution.py` — the "approved but not yet executed"
  retry path: `execute_approval()`'s idempotency, its 404/409 error
  mapping, and `resolve_approval()`'s `status` field.
- `test_cli_approval_flow.py` — the CLI itself, run as a real
  subprocess, through `simulate` → `review` → `approve`.

## Run the evals

```
python evals/run.py
```

A different artifact from the pytest suite above: not unit tests, a
*scored corpus* — 42 cases across every attack class this gate defends
against (forged signature, unknown principal, replay, expired mandate,
cross-merchant token misuse, amount-cap violation, invalid/negative/NaN
amount, category-scope violation) plus legitimate traffic that must
`ALLOW` (33% of the corpus — a corpus that's all attacks can't measure
false positives, which is the number that actually matters) and
`NEEDS_HUMAN` cases. Reports overall pass rate, block rate on attacks,
false-positive rate on legitimate traffic, and a per-attack-class
breakdown; exits non-zero on any mismatch, so it's CI-able — see
`evals/run.py`'s own docstring and `evals/dataset.jsonl`.

## CI

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

`.github/workflows/ci.yml` runs the full pytest suite and `evals/run.py`
on every push and pull request.
