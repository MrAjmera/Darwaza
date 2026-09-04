"""Append-only, hash-chained audit log.

Each entry stores sha256(previous entry's canonical JSON) so that
tampering with or deleting any past entry breaks the chain from that
point forward — verify_chain() walks the file and proves that. Each
entry also carries an explicit `seq` integer (Stage 3): chain order is
now *stated* by the entry itself, rather than *inferred* from where a
line happens to sit in the file — verify_chain() checks both the hash
link and the seq sequence, so a reordering or a removed-and-reinserted
line breaks verification even in a hypothetical scenario where the hash
chain alone somehow didn't already catch it.

Concurrency (Stage 3, D2): append_entry() used to read the file's last
line for prev_hash, then write — two concurrent callers could both read
the same prev_hash and both chain off it, forking the log even with no
tampering at all. This version wraps the whole read-tip-then-write
sequence in an OS-level lock (portalocker; works on Windows, unlike bare
fcntl), which makes it atomic across threads *and* processes. It also
caches each log file's tip (seq, hash) in memory after the first read,
which is what turns append_entry() from O(n) per call (previously: a
full re-read of the file every time) into O(1) after that first call —
this was measured at up to ~1.4ms/append at 16k entries before the fix.

Scope note, matching nonce_store.py and approval_queue.py: the tip
cache assumes this process is the sole writer to a given log file — the
same "one file for one instance" scope the rest of this system is
built to. If a second process appended to the same file without this
process observing it, the cache would go stale and the next append from
here would chain off the wrong tip; verify_chain() would then (as
designed) report exactly that as a break.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import portalocker

from darwaza.schema import Decision

# Hash of an empty string, used as prev_hash for the very first entry —
# there's nothing before it to hash, but every entry needs a prev_hash to
# keep the chain format uniform.
GENESIS_HASH = hashlib.sha256(b"").hexdigest()

# In-memory cache of each log file's current tip, keyed by resolved
# absolute path: (last_seq, last_entry_hash). See module docstring for
# what this buys (O(1) appends) and what it assumes (single-writer
# process per file).
_tip_cache: dict[str, tuple[int, str]] = {}
_tip_cache_lock = threading.Lock()


def _entry_hash(entry: dict) -> str:
    """Hash a full entry (including its own prev_hash and seq) so each
    link in the chain commits to everything that came before it, not just
    the immediately preceding hash."""
    canonical = json.dumps(entry, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scan_tip(log_path: Path) -> tuple[int, str]:
    """Read the whole file once to find the last entry's (seq, hash).
    O(n) — only ever called on a cache miss (see _tip_for()): the first
    time this process touches a given log path, or after a corrupt final
    line forces a re-scan.

    A partially-written final line (the process was killed mid-`write()`,
    a real possibility — see DECISIONS.md) is not treated as a broken
    chain here: it's an entry that was never really committed, so this
    stops at the last line that *did* parse and chains future appends off
    that, rather than raising and leaving the log permanently unwritable.
    verify_chain() is what reports that corruption to a caller who asks —
    scanning for the next append's tip and auditing the file for tamper
    evidence are different questions with different answers.
    """
    if not log_path.exists():
        return 0, GENESIS_HASH

    last_valid: tuple[int, str] | None = None
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                break
            last_valid = (entry.get("seq", 0), _entry_hash(entry))
    if last_valid is None:
        return 0, GENESIS_HASH
    return last_valid


def _tip_for(log_path: Path) -> tuple[int, str]:
    """Return the cached (seq, hash) tip for `log_path`, scanning the
    file once on first use and caching the result thereafter. Callers
    must hold the per-path file lock (see append_entry()) so a cache miss
    can't race against a concurrent append to the same file."""
    key = str(log_path.resolve())
    with _tip_cache_lock:
        cached = _tip_cache.get(key)
    if cached is not None:
        return cached
    tip = _scan_tip(log_path)
    with _tip_cache_lock:
        _tip_cache[key] = tip
    return tip


def _lock_path(log_path: Path) -> Path:
    # A dedicated sidecar lock file, rather than locking the JSONL file
    # itself, so readers (verify_chain(), a human tailing the file) never
    # contend with a writer's lock.
    return log_path.parent / (log_path.name + ".lock")


def append_entry(log_path: Path, mandate_id: str, decision: Decision) -> dict:
    """Append one decision to the log and return the entry that was written."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    key = str(log_path.resolve())

    with portalocker.Lock(str(_lock_path(log_path)), mode="a", timeout=10):
        last_seq, prev_hash = _tip_for(log_path)
        seq = last_seq + 1

        entry = {
            "seq": seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mandate_id": mandate_id,
            "outcome": decision.outcome.value,
            "reason": decision.reason,
            "failed_check": decision.failed_check,
            "prev_hash": prev_hash,
        }
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()

        with _tip_cache_lock:
            _tip_cache[key] = (seq, _entry_hash(entry))

    return entry


def verify_chain(log_path: Path) -> tuple[bool, str | None]:
    """Walk the log and confirm each entry's prev_hash matches the hash of
    the entry before it, and that seq increases by exactly 1 each time.
    Returns (True, None) if intact, or (False, reason) pointing at the
    first break found — a hash mismatch, a seq gap, or a line that isn't
    valid JSON at all (e.g. a partially-written final line from a crash
    mid-write). A tamper-evident log that raised an unhandled exception
    on the one kind of damage it exists to detect would defeat its own
    purpose as a dispute-reconstruction artifact.
    """
    if not log_path.exists():
        return True, None

    expected_prev_hash = GENESIS_HASH
    expected_seq = 1
    with log_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return False, (
                    f"line {line_num} is not valid JSON (corrupt or "
                    f"partially written): {exc}"
                )
            if entry.get("prev_hash") != expected_prev_hash:
                return False, f"chain broken at line {line_num} (mandate_id={entry.get('mandate_id')})"
            if entry.get("seq") != expected_seq:
                return False, (
                    f"sequence broken at line {line_num}: expected seq "
                    f"{expected_seq}, found {entry.get('seq')!r} "
                    f"(mandate_id={entry.get('mandate_id')})"
                )
            expected_prev_hash = _entry_hash(entry)
            expected_seq += 1

    return True, None
