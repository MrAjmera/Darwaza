"""Every credential and configurable path this system uses, loaded and
validated in one place, once, at import time — which is "process
startup" for both entry points: cli.py's imports run fresh at the top
of every CLI invocation, and api.py's run once when the ASGI app module
loads, before a single request is served.

Before this module existed, `RAZORPAY_KEY_ID`/`RAZORPAY_KEY_SECRET`
were only read inside `razorpay_client.create_order()` — meaning a
dangerous misconfiguration (a LIVE key, not a TEST key) would only be
discovered the moment a human approved a NEEDS_HUMAN request and this
demo tried to actually move money. That is the worst possible time to
discover it. Now it's discovered before the process can even finish
importing, so it can never reach that moment at all.

After this module, no other module in this package reads `os.environ`
directly — every other module imports what it needs from here
(`from darwaza import config`, then `config.SOME_VALUE`) instead.
Modules reference the `config` module itself, not
`from darwaza.config import SOME_VALUE`, specifically so tests can
`monkeypatch.setattr(config, "SOME_VALUE", ...)` and have every caller
see the patched value — a name-binding import would copy the value at
import time and no longer track it.
"""

from __future__ import annotations

import os
from pathlib import Path


class ConfigError(RuntimeError):
    """A credential is configured, but not safely — refuse to start
    rather than run with it."""


def redact(secret: str | None) -> str:
    """Return a version of `secret` safe to put in a log line or error
    message: never the real value. Used anywhere a structured log or
    startup message needs to say THAT a credential is configured
    without ever printing what it is (see observability.py)."""
    if not secret:
        return "<unset>"
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 6)}{secret[-2:]}"


# ---------------------------------------------------------------------------
# State file paths. Default to the repo root (stable regardless of the
# caller's cwd — this is a real gateway's persistent state, not scratch
# output). Overridable via env vars so tests, and a user who wants a
# clean isolated demo run, can point them elsewhere without touching the
# real repo-root files.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT_LOG_PATH = Path(os.environ.get("DARWAZA_AUDIT_LOG_PATH", str(REPO_ROOT / "audit_log.jsonl")))
NONCE_DB_PATH = Path(os.environ.get("DARWAZA_NONCE_DB_PATH", str(REPO_ROOT / "nonces.db")))
APPROVAL_DB_PATH = Path(os.environ.get("DARWAZA_APPROVAL_DB_PATH", str(REPO_ROOT / "approvals.db")))

# ---------------------------------------------------------------------------
# Credentials. Both are genuinely optional — this demo runs end-to-end
# without either (llm_explainer.py falls back to a deterministic
# template; razorpay_client.create_order() refuses loudly rather than
# silently no-opping). Neither package (anthropic, razorpay) is
# imported here or anywhere at module load — see those modules' own
# docstrings for why that stays true.
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or None
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID") or None
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET") or None


def _validate_razorpay_key_id(key_id: str | None) -> None:
    """Not configured at all is fine — that's a normal demo run without
    payment execution wired up, and razorpay_client.create_order()
    already fails loudly and specifically when that's the case (see
    DECISIONS.md #7). What's NOT fine is a key that's configured but
    isn't a Razorpay TEST-mode key: this project must never be able to
    move real money, so a `rzp_live_...` (or any other non-`rzp_test_`)
    key is refused outright, here, before anything else runs — not
    silently accepted and discovered dangerous later.

    Factored out from the module-level call below so it's testable on
    its own (tests/test_config.py) without needing a fresh process —
    the module-level call is what actually makes this "at startup" for
    real, since it runs unconditionally the moment this module is first
    imported.
    """
    if key_id is None:
        return
    if not key_id.startswith("rzp_test_"):
        raise ConfigError(
            f"RAZORPAY_KEY_ID ({redact(key_id)}) is not a Razorpay TEST-mode "
            "key (does not start with 'rzp_test_'). Refusing to start: this "
            "project is a demo that must never be able to move real money. "
            "Get test-mode keys from the Razorpay dashboard "
            "(Settings -> API Keys), or unset RAZORPAY_KEY_ID entirely to "
            "run without payment execution."
        )


_validate_razorpay_key_id(RAZORPAY_KEY_ID)
