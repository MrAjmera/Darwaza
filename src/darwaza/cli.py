"""Command-line entrypoint.

  python -m darwaza.cli decide <mandate.json> <proposed_tx.json>
  python -m darwaza.cli simulate <happy-path|poisoned-catalog>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from darwaza.audit_log import append_entry
from darwaza.nonce_store import NonceStore
from darwaza.policy_engine import evaluate
from darwaza.schema import NormalizedMandate, ProposedTransaction
from darwaza.simulate import SCENARIOS

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


def _print_decision(mandate_id: str, decision) -> None:
    print(f"Mandate:   {mandate_id}")
    print(f"Outcome:   {decision.outcome.value}")
    print(f"Reason:    {decision.reason}")
    print(f"Failed on: {decision.failed_check or '-'}")


def decide(mandate_path: str, tx_path: str) -> None:
    mandate = NormalizedMandate.model_validate(_load(mandate_path))
    proposed_tx = ProposedTransaction.model_validate(_load(tx_path))

    decision = evaluate(mandate, proposed_tx, _SEEN_NONCES)
    if decision.outcome.value == "ALLOW":
        _SEEN_NONCES.add(mandate.mandate_id)

    _print_decision(mandate.mandate_id, decision)

    entry = append_entry(DEFAULT_LOG_PATH, mandate.mandate_id, decision)
    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")
    print(f"  chained to prior entry: {entry['prev_hash'][:12]}...")


def simulate(scenario_name: str) -> None:
    if scenario_name not in SCENARIOS:
        print(f"Unknown scenario '{scenario_name}'. Known: {', '.join(SCENARIOS)}")
        sys.exit(1)

    scenario_fn = SCENARIOS[scenario_name]
    result = scenario_fn(log_path=DEFAULT_LOG_PATH, nonce_db_path=DEFAULT_NONCE_DB_PATH)

    print(f"Scenario:  {scenario_name}")
    _print_decision(result.mandate_id, result.decision)
    print(f"\nAudit log entry written to {DEFAULT_LOG_PATH}")


def main() -> None:
    usage = (
        "Usage:\n"
        "  python -m darwaza.cli decide <mandate.json> <proposed_tx.json>\n"
        "  python -m darwaza.cli simulate <" + "|".join(SCENARIOS) + ">"
    )
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    command = sys.argv[1]
    if command == "decide" and len(sys.argv) == 4:
        decide(sys.argv[2], sys.argv[3])
    elif command == "simulate" and len(sys.argv) == 3:
        simulate(sys.argv[2])
    else:
        print(usage)
        sys.exit(1)


if __name__ == "__main__":
    main()
