"""Single hardcoded Ed25519 keypair for demo signing/verification.

Scope cut (see DECISIONS.md): no key management, no rotation, no KMS, no
per-principal keys. One keypair stands in for "the principal's registered
signing key" for every mandate this system sees. In a real deployment
each principal (or their wallet/agent platform) would hold their own key,
registered with the merchant or PSP out of band — that registration and
rotation problem is explicitly out of scope for this build.

The private key below is checked into source control on purpose: this is
a demo keypair with no value outside this repo, and having it inline
(rather than in an untracked file) is what makes `evaluate()` runnable
and testable by anyone who clones the repo, with no setup step. This is
never acceptable for a real signing key.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# 32-byte raw Ed25519 seed, hex-encoded. Generated once for this project;
# fixed so signing/verification is reproducible across runs and machines
# without shipping a separate key file.
_PRIVATE_KEY_HEX = "08911626659cb98949a2fbf5a35e7d151a817fffe76a367657f144bf9e745b7f"

_private_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex(_PRIVATE_KEY_HEX)
)
_public_key: Ed25519PublicKey = _private_key.public_key()


def sign(message: bytes) -> str:
    """Sign `message` and return a base64-encoded signature. Used by the
    fixture/test signer and (later) the buyer-agent simulator to produce
    mandates that will pass verification — standing in for whatever
    signed the mandate in a real flow (a wallet, an agent platform)."""
    return base64.b64encode(_private_key.sign(message)).decode("ascii")


def verify(message: bytes, signature_b64: str) -> bool:
    """Return True iff `signature_b64` is a valid signature over `message`
    from the demo keypair's public key. Any malformed input (bad base64,
    wrong length, wrong key) is treated as an invalid signature, not an
    error — a forged or corrupted mandate should DENY, never crash the
    gateway."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        _public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
