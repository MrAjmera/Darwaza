"""Black-box integration test for the CLI's human-approval flow:
simulate a NEEDS_HUMAN case, list it via `review`, resolve it via
`approve`, and confirm it's gone from the pending list afterward.

Run as a real subprocess (not by importing cli.py's functions directly)
because cli.py's default paths and its module-level NonceStore are bound
at import time to the real repo root — running as a subprocess with a
temp working directory is what actually gets an isolated audit_log.jsonl
/ nonces.db / approvals.db per test, matching how a person would
actually run this from the command line.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = str(REPO_ROOT / "src")


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    import os

    env = dict(**os.environ)
    env["PYTHONPATH"] = SRC_PATH
    env.pop("ANTHROPIC_API_KEY", None)  # force the fallback explainer
    env.pop("RAZORPAY_KEY_ID", None)
    env.pop("RAZORPAY_KEY_SECRET", None)
    # Isolate state per test — without this, every invocation writes to
    # the same repo-root audit_log.jsonl/nonces.db/approvals.db
    # regardless of `cwd`, which is correct for real use (state lives
    # with the install, not wherever you happened to run the command
    # from) but means tests would collide with each other and with any
    # manual runs against the real repo.
    env["DARWAZA_AUDIT_LOG_PATH"] = str(cwd / "audit_log.jsonl")
    env["DARWAZA_NONCE_DB_PATH"] = str(cwd / "nonces.db")
    env["DARWAZA_APPROVAL_DB_PATH"] = str(cwd / "approvals.db")
    return subprocess.run(
        [sys.executable, "-m", "darwaza.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_needs_human_flows_through_review_and_approve(tmp_path):
    simulate_result = _run_cli(["simulate", "needs-human"], cwd=tmp_path)
    assert "NEEDS_HUMAN" in simulate_result.stdout, simulate_result.stdout + simulate_result.stderr

    match = re.search(r"request id: (\S+)", simulate_result.stdout)
    assert match, simulate_result.stdout
    request_id = match.group(1)

    review_result = _run_cli(["review"], cwd=tmp_path)
    assert request_id in review_result.stdout

    approve_result = _run_cli(["approve", request_id], cwd=tmp_path)
    assert "APPROVED" in approve_result.stdout
    # No Razorpay keys in this test env, so it should say so rather than
    # crash or silently pretend to have created an order.
    assert "Razorpay order not created" in approve_result.stdout

    review_after = _run_cli(["review"], cwd=tmp_path)
    assert "No pending approvals." in review_after.stdout


def test_approving_twice_fails_cleanly(tmp_path):
    simulate_result = _run_cli(["simulate", "needs-human"], cwd=tmp_path)
    match = re.search(r"request id: (\S+)", simulate_result.stdout)
    request_id = match.group(1)

    first = _run_cli(["approve", request_id], cwd=tmp_path)
    assert first.returncode == 0

    second = _run_cli(["approve", request_id], cwd=tmp_path)
    assert second.returncode != 0
    assert "already approved" in second.stdout
