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

---

## Entry 3 — NEEDS_HUMAN via a deterministic threshold rule

### What was missing before this
`evaluate()` could only ever return `ALLOW` or `DENY` — the `Outcome`
enum had a `NEEDS_HUMAN` value, but nothing produced it. There was no
answer yet to "when does something go to a human instead of being
auto-decided," which is a real design question, not an implementation
detail — get it wrong and either everything auto-approves (no human gate
at all) or the LLM ends up deciding it (breaks DECISIONS.md #2).

### What changed
- **`policy_engine.py`** — one new check (g.), run only for AP2-style
  mandates (the ones expressing a spending *ceiling*, not one exact
  transaction): if the proposed amount is more than
  `HUMAN_REVIEW_FRACTION_OF_CAP` (0.5, a named constant) of the
  mandate's `max_amount`, the outcome is `NEEDS_HUMAN`. ACP-style tokens
  (single-use, exact-amount) never hit this — there's no "fraction of a
  ceiling" concept for a token that only ever means one specific amount.
- This is a plain `if` statement — same style as every other check in
  `evaluate()`. No model, no judgment call, no ambiguity in what triggers
  it.

### The concept, in one line
An AP2-style mandate authorizes *up to* an amount for a category, not
one specific purchase — so a request that eats most of that ceiling in
one shot is structurally different from a small in-scope purchase, even
though both would pass every other check. Deciding *that* distinction
matters is a policy call a human made once, in code; deciding whether
*this specific request* crosses it is arithmetic, not judgment.

### How to see it work
```
cd darwaza
python -m darwaza.cli simulate poisoned-catalog   # -> DENY (amount_cap, not this)
```
See the tests below for the direct case — deliberately not wired into a
CLI fixture on its own yet, since it's about to be the trigger for the
LLM explainer and human approval gate in the next two entries.

Tests: `test_needs_human_when_ap2_amount_exceeds_review_threshold`,
`test_ap2_amount_at_threshold_boundary_still_auto_allows`,
`test_acp_never_needs_human_regardless_of_amount` in
`tests/test_policy_engine.py`.

### What it proves
That NEEDS_HUMAN is a real, reachable outcome — not just an enum value —
and that reaching it never requires a model. This is the deterministic
foundation the human approval gate (Entry 5) and the LLM explainer
(Entry 4) both build on.

### What to say in the pitch video
"NEEDS_HUMAN isn't the model's call — it's arithmetic against the
mandate's own stated ceiling. An AP2 mandate authorizes *up to* a
number; spending most of it in one request gets a human's eyes before
anything happens, every time, the same way, with no model in that
decision at all."

### What's still open after this entry
- The 0.5 threshold is a placeholder, not a tuned risk model — said so
  directly in DECISIONS.md #5, not presented as considered.
- The LLM judgment call, human approval gate, and Razorpay test-mode
  execution are all still unbuilt.

---

## Entry 4 — Buyer-agent simulator + a real poisoned-catalog attack

### What was missing before this
The adversarial suite could prove `evaluate()` denies a hand-crafted bad
transaction — but "prompt-injected buyer agent raising its own cap" and
"poisoned catalog manipulating the buyer's agent" were named attack
classes with no code behind them. Nothing existed that played the role
of the buying agent at all.

### What changed
Three new files, all under `src/darwaza/`:
- **`catalog.py`** — a tiny fake product catalog. One listing
  (`sku-poisoned-earbuds`) has a prompt-injection attempt embedded
  directly in its product description — the exact "seller descriptions,
  catalog metadata" surface DECISIONS.md #5 names as attacker-controlled.
- **`buyer_agent.py`** — `decide_deterministic()`: a rule-based "buying
  agent" (no model call, no API key needed) that picks the cheapest
  matching product. With `obey_injected_instructions=True`, it
  reproduces exactly what an unguarded LLM-based agent would do if it
  read that listing's text as an instruction instead of as data: it
  inflates its own proposed transaction to 999,999. (`decide_with_llm()`
  also exists — a real LLM reading the same catalog — but needs a live
  `ANTHROPIC_API_KEY` you supply and test yourself; it's not part of the
  automated suite because a live model call isn't reproducible enough to
  assert on.)
- **`simulate.py`** — wires a signed mandate + the buyer agent + the
  real `evaluate()` + the real audit log into runnable scenarios:
  `scenario_happy_path` and `scenario_poisoned_catalog`. Unlike
  `test_attacks.py`, these run the *actual agent*, not a hand-built
  transaction — the DENY is on whatever the (compromised) agent itself
  proposed.
- **`cli.py`** — new `simulate` subcommand:
  `python -m darwaza.cli simulate <happy-path|poisoned-catalog>`.

### The concept, in one line
Darwaza's whole premise only means something if there's a *separate,
untrusted* thing on the other side of it that can be attacked — this is
that thing, built deliberately attackable, so "the gate holds even when
the agent is compromised" is a claim you can run, not just assert.

### How to see it work
```
cd darwaza
python -m darwaza.cli simulate happy-path
# -> ALLOW: cheapest book, well within cap and category

python -m darwaza.cli simulate poisoned-catalog
# -> DENY, failed_check: amount_cap
# The "buyer agent" read a product description containing an injected
# instruction and inflated its own request to 999,999 — the mandate's
# real 1,000 cap still catches it.
```
Open `src/darwaza/catalog.py` and read the `sku-poisoned-earbuds` entry
to see the injected text itself.

Tests: `tests/test_buyer_agent.py` (the agent in isolation),
`tests/test_simulate.py` (full scenario + audit log), and
`test_attack_poisoned_catalog_is_denied` in `tests/test_attacks.py`
(same scenario, framed as the attack class it closes).

### What it proves
That a compromised buying agent — one that did exactly what a poisoned
listing told it to — still cannot get an oversized transaction past the
gate. This is the difference between "the policy engine has a test for
amount caps" and "the system holds up when the thing feeding it input is
actively working against it," which is the actual threat model Darwaza
claims to defend.

### What to say in the pitch video
"This isn't a hypothetical — here's a product listing with an injection
attempt baked into its description, here's a buying agent that reads it
and does what it says, and here's the transaction it tries to submit:
999,999 rupees. And here's the gate denying it anyway, because the real
cap lives in the mandate, not in anything the agent — compromised or
not — gets to say about itself."

### What's still open after this entry
- `decide_with_llm()` exists but isn't part of the automated suite —
  running the *real* version of this attack (a live LLM actually being
  manipulated, not a deterministic stand-in) requires a key you supply.
- The LLM explainer (downstream-only, see DECISIONS.md #6) and the human
  approval gate for NEEDS_HUMAN cases are still unbuilt.
- Razorpay test-mode execution is still unbuilt.
