# Darwaza

A protocol-agnostic, merchant-side authorization gateway for AI buying
agents. Given a mandate (an AP2-style intent mandate or an ACP-style
scoped token) and a proposed transaction, Darwaza deterministically
decides **ALLOW / DENY / NEEDS_HUMAN**, gets human sign-off for anything
flagged, and writes a tamper-evident audit trail for every step. See
[DECISIONS.md](DECISIONS.md) for why it's built this way, decision by
decision, and [docs/BUILD_LOG.md](docs/BUILD_LOG.md) for a plain-language,
step-by-step account of how it was built.

## What's real vs. what's scoped out

**Real:** normalized mandate schema (AP2 and ACP asymmetry preserved,
not papered over), a pure deterministic policy engine (6 checks, zero
LLM calls in the enforcement path), real Ed25519 signature verification,
persistent SQLite-backed replay detection, a hash-chained tamper-evident
audit log, a buyer-agent simulator with a real (not just unit-tested)
poisoned-catalog attack, an LLM explainer that is structurally unable to
influence a decision, a human approval queue, and Razorpay test-mode
order creation.

**Explicitly out of scope**, named directly rather than hidden: key
management/rotation (one hardcoded demo keypair stands in for every
principal), multi-instance coordination (the nonce store and approval
queue are each a single SQLite file), a full payment round-trip without
a frontend (Razorpay integration stops at order creation), and a tuned
risk model behind the 0.5 human-review threshold (it's a defensible
round number, not derived from data). See DECISIONS.md's "Open items"
for the complete list.

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
```

Set `ANTHROPIC_API_KEY` before `simulate needs-human` to get a real LLM
explanation instead of the labeled fallback template. Set
`RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` (test-mode keys, from your
Razorpay dashboard) before `approve` to create a real Razorpay test-mode
order.

Every run appends to `audit_log.jsonl` in the repo root (gitignored —
it's runtime state, not source). `nonces.db` and `approvals.db` are the
same: gitignored, persistent, safe to delete to reset the demo.

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
- `test_cli_approval_flow.py` — the CLI itself, run as a real
  subprocess, through `simulate` → `review` → `approve`.
