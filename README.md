# Darwaza

A merchant-side authorization gateway for AI buying agents. Given a
mandate (AP2-style intent mandate or ACP-style scoped token) and a
proposed transaction, Darwaza deterministically decides
ALLOW / DENY / NEEDS_HUMAN and writes a tamper-evident audit log entry.

This is a v1 slice: no Razorpay API calls, no protocol adapters, no LLM
calls anywhere. See [DECISIONS.md](DECISIONS.md) for why, and for the
current open items (signature verification and replay storage are both
stubbed for now).

## Setup

```
cd darwaza
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

## Run the demo

```
python -m darwaza.cli decide tests/fixtures/ap2_mandate.json tests/fixtures/ap2_proposed_tx.json
python -m darwaza.cli decide tests/fixtures/acp_token.json tests/fixtures/acp_proposed_tx.json
python -m darwaza.cli decide tests/fixtures/expired_mandate.json tests/fixtures/expired_proposed_tx.json
```

Each run prints the decision and appends an entry to `audit_log.jsonl` in
the repo root (gitignored — it's runtime state, not source).

## Run the tests

```
python -m pytest
```

`tests/test_policy_engine.py` covers each check in `evaluate()` in
isolation. `tests/test_attacks.py` frames the same checks as adversarial
scenarios (replay, expiry, cross-merchant use, cap-exceeding requests).
