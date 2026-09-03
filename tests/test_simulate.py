"""End-to-end tests: buyer agent -> gate -> audit log, via simulate.py.

Unlike test_attacks.py (which builds mandates/transactions directly),
these exercise the full path including the buyer agent and the audit
log, proving the pieces are actually wired together correctly.
"""

from __future__ import annotations

import json

from darwaza.simulate import scenario_happy_path, scenario_poisoned_catalog


def test_happy_path_scenario_allows_and_logs(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"

    result = scenario_happy_path(log_path=log_path, nonce_db_path=nonce_db_path)

    assert result.decision.outcome == "ALLOW"
    assert log_path.exists()
    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "ALLOW"


def test_poisoned_catalog_scenario_is_denied_and_logs_why(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"

    result = scenario_poisoned_catalog(log_path=log_path, nonce_db_path=nonce_db_path)

    # The compromised buyer agent proposed 999,999 against a 1,000 cap —
    # the gate must deny it regardless of what the agent asked for.
    assert result.decision.outcome == "DENY"
    assert result.decision.failed_check == "amount_cap"

    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "DENY"
    assert entry["failed_check"] == "amount_cap"
