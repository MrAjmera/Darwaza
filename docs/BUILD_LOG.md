# Build log

Plain-language log of what got built, in order, written so it can be read
*after* the fact — not required reading before building. Each entry: what
we built, why it matters for the theory, how to see it work, and what to
say about it if a panel asks.

---

## Entry 1 — Real Ed25519 signature verification

### What was stubbed before this
`policy_engine.verify_signature()` always returned `True`. So the
"signature" check in `evaluate()` existed in the code and in the test
list, but did nothing — any mandate, forged or not, passed it.

### What changed
Three new pieces, all under `src/darwaza/`:

- **`keys.py`** — one hardcoded Ed25519 keypair (a public/private key
  pair used for digital signatures — think of the private key as "the
  only thing that can produce a valid signature," and the public key as
  "the only thing that can check one"). `sign(bytes) -> signature` and
  `verify(bytes, signature) -> bool`.
- **`schema.py`: `NormalizedMandate.signing_payload()`** — turns a
  mandate's fields (everything except the signature itself) into one
  fixed, deterministic byte string. "Deterministic" matters here: the
  signer and the verifier must compute the *exact same bytes* from the
  *exact same fields*, or a legitimate signature would look invalid just
  from serialization drift (field order, whitespace, etc.).
- **`policy_engine.py`: `verify_signature()`** — now calls
  `keys.verify(mandate.signing_payload(), mandate.signature)` for real.

### The concept, in one line
A signature proves two things at once: *who* signed something (only the
private-key holder could have produced a signature the public key
accepts), and *that it hasn't been changed since* (change one field,
the payload bytes change, the old signature no longer matches).
That second property — tamper-evidence — is what closes the gap a naive
reading of "check the signature" misses: it's not just "is a signature
present," it's "does this signature match *these exact* fields."

### How to see it work
```
cd darwaza
# activate your venv, then:
python -m darwaza.cli decide tests/fixtures/ap2_mandate.json tests/fixtures/ap2_proposed_tx.json
```
That mandate fixture now carries a real signature (regenerated with the
demo key) and passes. To see it fail, open
`tests/fixtures/ap2_mandate.json`, change any field (e.g. `max_amount`),
save, and re-run the same command — outcome flips to `DENY`,
`failed_check: signature`, because the payload no longer matches what was
signed.

Tests: `pytest -q` — includes `test_signature_valid_passes`,
`test_signature_garbage_fails`, `test_signature_tampered_field_fails`
(unit level) and `test_attack_forged_signature_is_denied` (adversarial
suite — an agent impersonating a principal it doesn't hold the key for).

### What it proves
That the gateway can tell a genuinely-authorized mandate from one an
attacker fabricated or altered, using math, not trust. This closes one
of the four differentiators (the adversarial suite) for real, rather than
leaving it as a check that always passes.

### What to say in the pitch video
"Signature verification isn't just 'is there a signature field' — it's
cryptographic proof the mandate is exactly what the principal signed,
unmodified. If an agent tries to raise its own spend cap after the
mandate was issued, the signature breaks and the gate denies it before
any other check even runs." Then, honestly: "This build uses one
hardcoded keypair standing in for every principal — real key issuance and
rotation per principal is out of scope, and that's named as an open item,
not hidden."

### What's still open after this entry
- Replay detection is in-memory only (not persistent across restarts).
- Key management (issuance, rotation, per-principal keys) doesn't exist —
  by design, see DECISIONS.md #3.
- Buyer-agent simulator, the one LLM judgment call, human approval gate,
  and Razorpay test-mode execution are all still unbuilt.

---

## Entry 2 — Persistent replay detection (SQLite nonce store)

### What was stubbed before this
The CLI kept spent mandate ids in a plain Python `set()`. That set lived
only in process memory — every time the CLI process exited (which is
every single command, since `python -m darwaza.cli decide ...` runs
once and quits), the set was thrown away. So the second half of the
"replayed mandate" attack test was true in the test suite (same process,
same set) but false in reality (separate process each time): you could
replay a mandate for real just by re-running the command.

### What changed
- **`src/darwaza/nonce_store.py`** (new) — `NonceStore`, backed by a
  small SQLite file, with the same two operations code already used on
  the in-memory set: `mandate_id in store` and `store.add(mandate_id)`.
- **`cli.py`** — swapped `_SEEN_NONCES: set[str] = set()` for
  `NonceStore(DEFAULT_NONCE_DB_PATH)`, writing to `nonces.db` next to
  `audit_log.jsonl`.
- **`policy_engine.evaluate()` did not change at all.** It never knew or
  cared whether `seen_nonces` was a `set()` or something else — it only
  ever called `in` and relied on the caller to call `.add()`. That's why
  this was a safe, small change: the enforcement logic stayed exactly as
  pure and untouched as DECISIONS.md #2 requires.

### The concept, in one line
"Replay protection" only means something if the record of what's already
been spent survives as long as the mandate itself could be replayed —
memory that resets on restart isn't a record, it's a coincidence that
happened to work during one continuous run.

### How to see it work
```
cd darwaza
python -m darwaza.cli decide tests/fixtures/ap2_mandate.json tests/fixtures/ap2_proposed_tx.json
# -> ALLOW (first use)
python -m darwaza.cli decide tests/fixtures/ap2_mandate.json tests/fixtures/ap2_proposed_tx.json
# -> DENY, failed_check: replay — even though this is a brand-new process
```
Before this entry, the second run above would have said ALLOW again,
because the first run's in-memory set no longer existed. A `nonces.db`
SQLite file appears in the repo root after the first run — delete it to
reset the demo state.

Tests: `pytest -q` — `tests/test_nonce_store.py`, especially
`test_persists_across_separate_store_instances`, which is the exact bug
this entry fixes, written as a test (two separate `NonceStore` objects
pointed at the same file, simulating a process restart).

### What it proves
That "replay detection" is real across restarts, not just within one
Python process — the gap between "looks correct in a demo" and "would
actually stop a replay attack in the field" is closed for this one
check.

### What to say in the pitch video
"The replay check isn't just logic — it's backed by a file on disk, so
restarting the service doesn't reset what counts as already-spent. This
is one SQLite file for one instance, which is honestly scoped: it's not
solving replay protection across multiple horizontally-scaled instances,
and that's named directly in DECISIONS.md, not glossed over."

### What's still open after this entry
- Multi-instance coordination isn't solved (see DECISIONS.md #4) — fine
  for a demo/single-instance system, not for a scaled deployment.
- Key management is still out of scope by design.
- Buyer-agent simulator, the one LLM judgment call, human approval gate,
  and Razorpay test-mode execution are all still unbuilt.
