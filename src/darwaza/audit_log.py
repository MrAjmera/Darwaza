"""Append-only, hash-chained audit log.

Each entry stores sha256(previous entry's canonical JSON) so that
tampering with or deleting any past entry breaks the chain from that
point forward — verify_chain() walks the file and proves that.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from darwaza.schema import Decision

# Hash of an empty string, used as prev_hash for the very first entry —
# there's nothing before it to hash, but every entry needs a prev_hash to
# keep the chain format uniform.
GENESIS_HASH = hashlib.sha256(b"").hexdigest()


def _entry_hash(entry: dict) -> str:
    """Hash a full entry (including its own prev_hash) so each link in the
    chain commits to everything that came before it, not just the
    immediately preceding hash."""
    canonical = json.dumps(entry, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash(log_path: Path) -> str:
    if not log_path.exists():
        return GENESIS_HASH
    last_line = None
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return GENESIS_HASH
    return _entry_hash(json.loads(last_line))


def append_entry(log_path: Path, mandate_id: str, decision: Decision) -> dict:
    """Append one decision to the log and return the entry that was written."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mandate_id": mandate_id,
        "outcome": decision.outcome.value,
        "reason": decision.reason,
        "failed_check": decision.failed_check,
        "prev_hash": _last_hash(log_path),
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_chain(log_path: Path) -> tuple[bool, str | None]:
    """Walk the log and confirm each entry's prev_hash matches the hash of
    the entry before it. Returns (True, None) if intact, or
    (False, reason) pointing at the first break found.
    """
    if not log_path.exists():
        return True, None

    expected_prev_hash = GENESIS_HASH
    with log_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != expected_prev_hash:
                return False, f"chain broken at line {line_num} (mandate_id={entry.get('mandate_id')})"
            expected_prev_hash = _entry_hash(entry)

    return True, None
