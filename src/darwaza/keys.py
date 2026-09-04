"""Per-principal Ed25519 keypairs for demo signing/verification.

Stage 7 replaces what used to be here: ONE hardcoded keypair, shared by
every principal in the system regardless of which principal_id a mandate
claimed. That was more dangerous than its old docstring admitted.
`policy_engine.verify_signature()` only ever proved "this mandate was
signed by whoever holds the one demo private key" — it could not prove
"principal p1 specifically signed this, and not principal p2," because
every principal shared the same key and the signature check was never
tied to the `principal_id` field it was supposedly authenticating. A
mandate signed for real (with the one shared key) but with its
`principal_id` field changed to claim a *different* principal than
whoever actually holds the key passed verification cleanly — see
tests/test_attacks.py's forged-principal-id test, which proves this was
real before this stage, not a theoretical gap.

The fix is a small per-principal registry, not a key-management system:
`_PRIVATE_KEYS`/`_PUBLIC_KEYS` map `principal_id -> keypair`, and
`verify()` now takes `principal_id` as a required argument, looks up
*that* principal's registered public key, and checks the signature
against *only that key* — so the check becomes "does this signature
verify against this specific principal's registered key," not "does
this signature verify against some key somewhere in the system." An
unregistered `principal_id` fails verification (see verify()'s
docstring) — same as a bad signature — rather than raising, and
policy_engine.py surfaces that as its own DENY reason
(`failed_check="unknown_principal"`) distinct from a wrong-but-
registered signature, so an audit-log reader can tell "we don't know
this principal" apart from "we know this principal and the signature
doesn't match."

Scope, precisely bounded (this is the sentence that matters if asked
"so is key management solved now"): this stage moves the honest scope
boundary from "key management is entirely absent" to "key verification
is correctly scoped to per-principal demo keys; key management
(issuance, rotation, revocation) remains out of scope." What's still
NOT here, on purpose:
- **No rotation.** A principal's key is fixed for the life of this
  file; there is no "old key still valid during a grace period" concept.
- **No registration/enrollment flow.** Adding a fourth principal means
  editing this file and redeploying, not an API call that provisions
  one at runtime. That's the actual difference between "a demo registry"
  and "a KMS," and it's still true after this fix — this stage makes the
  registry *correct* for the principals it knows about, not *dynamic*.
- **No persistence beyond this file.** No database table, no config
  file loaded at startup — three principals, hardcoded, same spirit as
  the single keypair this replaces.
- **No KMS/HSM/external key-management integration of any kind.**

Private keys are checked into source control on purpose, same reasoning
as before this stage: these are demo keypairs with no value outside
this repo, and inlining them (rather than untracked key files) is what
makes the test suite and the CLI demo runnable by anyone who clones the
repo, with no setup step. This is never acceptable for a real signing
key.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# 32-byte raw Ed25519 seeds, hex-encoded, one per demo principal. Fixed
# (not generated at import time) so signing/verification is reproducible
# across runs and machines without shipping separate key files — same
# reasoning as the single seed this replaces, just one per principal now.
# "user-krishna" reuses the original single-keypair seed from before this
# stage, so every existing fixture/demo that already names that
# principal keeps working without a key change, only a scope change (its
# key is no longer also everyone else's key).
_PRIVATE_KEY_SEEDS_HEX: dict[str, str] = {
    "user-krishna": "08911626659cb98949a2fbf5a35e7d151a817fffe76a367657f144bf9e745b7f",
    "p1": "61fd0683010573362024de78455a9e328c0b77c6f3158f1426f473bfd71d7a7c",
    "p2": "8830f9ea36bdcf3c7b64507514e53baa49878436ecfa5daaabc579db11e0cbb7",
}

_PRIVATE_KEYS: dict[str, Ed25519PrivateKey] = {
    principal_id: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    for principal_id, seed_hex in _PRIVATE_KEY_SEEDS_HEX.items()
}

# The actual trust registry: what verify_signature() checks against.
# Deliberately derived from _PRIVATE_KEYS (each public key is exactly
# its matching private key's public half) rather than listed
# separately — a real deployment would never hold private keys at all
# here, only this half, registered out of band per principal; keeping
# them derived in this demo file at least rules out the public/private
# pairs in this file ever drifting apart from each other by a copy-paste
# mistake.
PUBLIC_KEYS: dict[str, Ed25519PublicKey] = {
    principal_id: private_key.public_key() for principal_id, private_key in _PRIVATE_KEYS.items()
}


def sign(principal_id: str, message: bytes) -> str:
    """Sign `message` as `principal_id` and return a base64-encoded
    signature, using that principal's demo private key. Used by the
    fixture/test signer and the buyer-agent simulator to produce
    mandates that will pass verification — standing in for whatever
    signed the mandate in a real flow (a wallet, an agent platform).

    Raises `KeyError` for a `principal_id` with no registered demo
    keypair — unlike `verify()` below, there is no "fail closed"
    obligation here: this is a test/fixture helper, never called on the
    enforcement path, so a typo'd principal_id should surface loudly and
    immediately (a KeyError at fixture-build time), not produce a
    signature that will only turn out to be meaningless later."""
    return base64.b64encode(_PRIVATE_KEYS[principal_id].sign(message)).decode("ascii")


def verify(principal_id: str, message: bytes, signature_b64: str) -> bool:
    """Return True iff `signature_b64` is a valid signature over
    `message` from `principal_id`'s *own* registered demo public key.

    An unrecognized `principal_id` is not an error/exception here — it's
    a normal "verification fails," exactly like a bad signature: an
    unregistered principal has no key to check against, so there is
    nothing to trust, the same conclusion a wrong signature reaches by a
    different road. This function does not distinguish the two cases in
    its return value on purpose (both are simply False) — the caller
    (policy_engine.verify_signature() / evaluate()) is what decides
    whether "unregistered principal" deserves a different DENY reason
    (`failed_check="unknown_principal"`) than "registered principal,
    wrong signature" (`failed_check="signature"`), by checking
    `principal_id in PUBLIC_KEYS` itself before ever calling this. This
    function's job stays narrow: does this exact signature verify
    against this exact principal's key, yes or no.

    Any malformed input (bad base64, wrong length, wrong key) is also
    treated as an invalid signature, not an error — a forged or
    corrupted mandate should DENY, never crash the gateway."""
    public_key = PUBLIC_KEYS.get(principal_id)
    if public_key is None:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
