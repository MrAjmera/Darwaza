# Decisions

This file records why Darwaza is built the way it is, not just what it does.
Each entry: what we chose, what we rejected, and why.

## 1. Normalize two protocol shapes instead of integrating one protocol deeply

**Chosen:** Darwaza defines a single `NormalizedMandate` shape that both an
AP2-style Intent Mandate and an ACP-style scoped token get mapped into
before they ever reach the policy engine. The engine only ever sees the
normalized shape — it has no knowledge of AP2 or ACP as protocols.

**Rejected:** Building a deep, first-class integration with one protocol
(e.g. fully implementing AP2's mandate chain, delegation semantics, and
crypto suite) and treating the other as an afterthought or a later
"adapter."

**Why:** The whole point of a merchant-side authorization gateway is that
merchants will face buying agents speaking *different* protocols, and new
ones will show up. If the policy engine is written against one protocol's
assumptions, every new protocol requires touching enforcement logic — the
highest-risk code in the system. Normalizing early means protocol-specific
parsing is a thin, swappable layer, and the enforcement logic is written
once against a stable shape. It also forces an honest question up front:
what do these protocols actually guarantee in common? (Answer, see
decision below and `schema.py`: not much — ACP tokens don't carry stated
intent at all.) A deep single-protocol integration would have hidden that
asymmetry instead of surfacing it as a first-class modeling concern.

## 2. The policy engine is pure deterministic code with zero LLM calls in the enforcement path

**Chosen:** `evaluate()` is a pure function: same inputs always produce the
same output, no network calls, no model inference, no hidden state beyond
an explicitly-passed replay set. Every check it performs (signature,
expiry, replay, merchant match, amount cap, category scope) is a plain
comparison against fields already present in the mandate and the proposed
transaction.

**Rejected:** Using an LLM to review the proposed transaction against the
mandate's intent and decide ALLOW/DENY/NEEDS_HUMAN, which is the more
"agentic" and flexible-looking option and was tempting given the rest of
the system talks to AI buying agents.

**Why:** This is an authorization gateway — its job is to be the thing you
can trust *even when* the agents on either side of it are compromised,
buggy, or being actively attacked (prompt injection, adversarial catalog
data, etc.). An LLM in the enforcement path means the gate itself becomes
attackable by the same techniques used against buying agents, and its
decisions stop being reproducible or auditable in the way a hash-chained
log demands — "the model said no" is not a defensible answer to a
merchant or a regulator. Determinism also makes the test suite meaningful:
`test_attacks.py` can assert an exact DENY for an exact reason, which is
not possible against a system with non-deterministic reasoning. If natural-language
reasoning is ever useful (e.g. summarizing *why* something looks
suspicious for a human reviewer), it belongs strictly downstream of the
ALLOW/DENY/NEEDS_HUMAN decision, never as part of making it.

## 3. Ed25519 signature verification with one hardcoded demo keypair

**Chosen:** `NormalizedMandate.signing_payload()` (schema.py) serializes
every field except `signature` into deterministic bytes (sorted keys,
fixed separators). `keys.sign()`/`keys.verify()` wrap a single hardcoded
Ed25519 keypair. `policy_engine.verify_signature()` now actually checks:
does this signature verify against these exact bytes, with this key? Any
mismatch — forged signature, or a legitimate signature over fields that
were changed afterward — returns False, which `evaluate()` turns into
`DENY / failed_check="signature"`.

**Rejected (for this build):** Per-principal keys with a registration
flow; a KMS or hardware-backed key store; key rotation.

**Why:** The signature check exists to answer one question: did the
transaction the gate is looking at actually come from something the
principal signed, unmodified? A single fixed keypair is enough to prove
that mechanism works — real forgery is rejected, real tampering is
detected — without building the much bigger (and out-of-scope, see the
build plan's cuts) problem of key management for many principals. This
is explicitly a demo shortcut, not a claim that key management is solved;
said so directly in the code (`keys.py`) and here, so it can't be
mistaken for something it isn't in front of a panel.

**What changed as a result:** every mandate fixture and every mandate
built in the tests now carries a real signature (see `_signed()` helpers
in `test_policy_engine.py` / `test_attacks.py`, and the regenerated
`tests/fixtures/*.json`). A new adversarial test,
`test_attack_forged_signature_is_denied`, covers the attack class this
closes: an agent impersonating a principal it doesn't represent, without
holding that principal's key.

## 4. Persistent replay detection via a single-table SQLite store

**Chosen:** `nonce_store.py` adds `NonceStore`, a thin SQLite-backed
class implementing exactly the two operations `evaluate()` already used
on `seen_nonces` — `x in store` and `store.add(x)`. The CLI now passes a
`NonceStore` pointed at `nonces.db` instead of a `set()`.

**Rejected:** A "real" queue/cache system (Redis, a message broker);
changing `evaluate()`'s signature to take something more specific than
"a thing that supports `in` and `add`."

**Why:** The bug being fixed is narrow: a mandate marked as spent must
stay spent after the process restarts. SQLite in a single file solves
exactly that, with no new service to run or configure — appropriate for
a demo/single-merchant-instance system, called out explicitly as not
sufficient for multiple concurrent instances (see open items). Keeping
`evaluate()`'s parameter untyped beyond "supports `in`/`add`" means the
pure-function contract from decision #2 doesn't change at all — tests
can still pass a plain `set()`, and the persistence choice lives entirely
in the caller (the CLI), not in the policy engine.

## Open items

- **Multi-instance replay protection isn't solved.** A single SQLite
  file is correct for one process/one merchant instance, but doesn't
  coordinate across multiple concurrent instances (e.g. horizontally
  scaled) the way a shared service (Redis, a real DB) would.
- **Key management is out of scope.** One hardcoded keypair stands in for
  every principal (see decision 3 above) — no registration, issuance, or
  rotation flow exists.
