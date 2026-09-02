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

## Open items

- **Signature verification is stubbed.** `policy_engine.verify_signature()`
  currently always returns `True`. Real Ed25519 verification is out of
  scope for this session and needs to be implemented before this system
  handles anything real. Until then, the "signature valid" check is not
  actually checking anything.
- **Replay detection is in-memory only.** The seen-nonce set used to
  detect replayed mandates lives in process memory and is lost on
  restart, and won't work across multiple instances. It needs to move to
  persistent storage (e.g. a database or Redis) before this is anything
  more than a demo.
