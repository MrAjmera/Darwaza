"""Command-line entrypoint: python -m darwaza.cli decide <mandate.json> <proposed_tx.json>"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction

DEFAULT_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "audit_log.jsonl"
DEFAULT_NONCE_DB_PATH = Path(__file__).resolve().parent.parent.parent / "nonces.db"

# Persistent across CLI invocations and process restarts — see
# nonce_store.py and DECISIONS.md. Previously an in-memory set() that
# reset every run, which meant replay protection only worked within a
# single process's lifetime.
_SEEN_NONCES = NonceStore(DEFAULT_NONCE_DB_PATH)


def _load(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def decide(mandate_path: str, tx_path: str) -> None:
    mandate = NormalizedMandate.model_validate(_load(mandate_path))
    proposed_tx = ProposedTransaction.model_validate(_load(tx_path))

    decision = evaluate(mandate, proposed_tx, _SEEN_NONCES)
    if decision.outcome.value == "ALLOW":
        _SEEN_NONCES.add(mandate.mandate_id)

    print(f"Mandate:   {mandate.mandate_id}")
    print(f"Outcome:   {decision.outcome.value}")
    print(f"Reason:    {decision.reason}")
    print(f"Failed on: {decision.failed_check or '-'}")

    entry = append_entry(DEFAULT_LOG_PATH, mandate.mandate_id, decision)
    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")
    print(f"  chained to prior entry: {entry['prev_hash'][:12]}...")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] != "decide":
        print("Usage: python -m darwaza.cli decide <mandate.json> <proposed_tx.json>")
        sys.exit(1)
    decide(sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
