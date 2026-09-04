"""End-to-end tests: buyer agent -> gate -> audit log -> (NEEDS_HUMAN
only) explain + enqueue, via simulate.py.

Unlike test_attacks.py (which builds mandates/transactions directly),
these exercise the full path including the buyer agent and the audit
log, proving the pieces are actually wired together correctly.

As of Stage 4, scenario functions route through service.authorize()
(see simulate.py), so a NEEDS_HUMAN scenario now also enqueues into the
approval queue — it didn't before this refactor (only cli.py's
`simulate` command did that, separately, after calling the scenario).
Every call below passes an isolated `approval_db_path` for the same
reason `log_path`/`nonce_db_path` are isolated: without it, a
NEEDS_HUMAN scenario would silently write into the real repo's
approvals.db.
"""

from __future__ import annotations

import json

from darwaza.approval_queue import ApprovalQueue
from darwaza.simulate import (
    scenario_happy_path,
    scenario_large_purchase_needs_human,
    scenario_poisoned_catalog,
)


def test_happy_path_scenario_allows_and_logs(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"

    result = scenario_happy_path(
        log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )

    assert result.decision.outcome == "ALLOW"
    assert result.request_id is None  # never enqueued -- only NEEDS_HUMAN is
    assert log_path.exists()
    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "ALLOW"


def test_poisoned_catalog_scenario_is_denied_and_logs_why(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"

    result = scenario_poisoned_catalog(
        log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )

    # The compromised buyer agent proposed 999,999 against a 1,000 cap —
    # the gate must deny it regardless of what the agent asked for.
    assert result.decision.outcome == "DENY"
    assert result.decision.failed_check == "amount_cap"

    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "DENY"
    assert entry["failed_check"] == "amount_cap"


def test_large_purchase_scenario_needs_human_and_logs(tmp_path):
    log_path = tmp_path / "audit_log.jsonl"
    nonce_db_path = tmp_path / "nonces.db"
    approval_db_path = tmp_path / "approvals.db"

    result = scenario_large_purchase_needs_human(
        log_path=log_path, nonce_db_path=nonce_db_path, approval_db_path=approval_db_path
    )

    assert result.decision.outcome == "NEEDS_HUMAN"
    assert result.decision.failed_check == "human_review_threshold"

    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "NEEDS_HUMAN"

    # Stage 4: the scenario now goes through service.authorize() end to
    # end, so a NEEDS_HUMAN result must also be explained and enqueued —
    # not just logged.
    assert result.request_id is not None
    assert result.explanation is not None
    queue = ApprovalQueue(approval_db_path)
    try:
        row = queue.get(result.request_id)
    finally:
        queue.close()
    assert row is not None
    assert row["status"] == "pending"
    assert row["mandate_id"] == result.mandate_id
