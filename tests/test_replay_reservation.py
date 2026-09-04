"""D4: NEEDS_HUMAN must reserve the mandate's nonce, exactly like ALLOW
does. Today, cli.decide()/cli.simulate() only call _SEEN_NONCES.add() on
ALLOW -- a mandate that routes to NEEDS_HUMAN goes into the approval queue
without being marked spoken-for, so it stays claimable by anyone, and can
be submitted again and again, each time producing a new pending approval
for what should be one single-use authorization.

Run as real subprocesses (not by importing cli.py's functions directly)
for the same reason tests/test_cli_approval_flow.py does: cli.py's default
paths and its module-level NonceStore are bound at import time to the real
repo root, so a subprocess with an isolated cwd is what actually gets a
clean audit_log.jsonl / nonces.db / approvals.db per test.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = str(REPO_ROOT / "src")


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    env = dict(**os.environ)
    env["PYTHONPATH"] = SRC_PATH
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("RAZORPAY_KEY_ID", None)
    env.pop("RAZORPAY_KEY_SECRET", None)
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


def test_D4_needs_human_reserves_nonce_so_it_cannot_be_resubmitted(tmp_path):
    """The 'needs-human' scenario builds a fresh signed mandate with a
    FIXED mandate_id ('sim-needs-human-1') every call. Submitting it three
    times should only ever produce ONE pending approval -- the first
    submission reserves the nonce, and the second/third should be denied
    as replays before they ever reach the queue."""
    for _ in range(3):
        result = _run_cli(["simulate", "needs-human"], cwd=tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr

    review_result = _run_cli(["review"], cwd=tmp_path)
    pending_count = review_result.stdout.count("mandate=sim-needs-human-1")

    assert pending_count == 1, (
        f"expected exactly one pending approval for a single-use mandate "
        f"submitted 3 times, got {pending_count}. Full review output:\n"
        f"{review_result.stdout}"
    )


def test_D4_only_one_of_the_duplicate_approvals_can_be_approved(tmp_path):
    """The sharper consequence of D4: before the nonce-reservation fix,
    not just duplicate queue rows are created, but each is independently
    approvable -- three separate 'APPROVED' resolutions (and, with real
    Razorpay keys, three real orders) for one authorization that should
    only ever be spendable once. After the fix, only the first
    submission ever reaches NEEDS_HUMAN at all (the second and third are
    denied as replays before enqueueing), so this collects whatever
    request ids actually got created and asserts on how many of *those*
    end up approved -- correct either way the queue got populated."""
    request_ids = []
    for _ in range(3):
        result = _run_cli(["simulate", "needs-human"], cwd=tmp_path)
        match = re.search(r"request id: (\S+)", result.stdout)
        if match:
            request_ids.append(match.group(1))

    approved_count = 0
    for rid in request_ids:
        result = _run_cli(["approve", rid], cwd=tmp_path)
        if "APPROVED" in result.stdout:
            approved_count += 1

    assert approved_count == 1, (
        f"expected exactly 1 of the {len(request_ids)} queued request(s) "
        f"for this single-use mandate to be approvable, but "
        f"{approved_count} were approved -- one authorization would "
        f"produce {approved_count} Razorpay orders"
    )
