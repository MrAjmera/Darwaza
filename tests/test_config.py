"""Unit tests for config.py's pure validation/redaction logic, plus one
subprocess-level test proving the actual "at startup" behavior: a
misconfigured RAZORPAY_KEY_ID crashes the process before it can do
anything, not just when create_order() happens to be called.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from darwaza import config

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = str(REPO_ROOT / "src")


def test_redact_none_is_unset():
    assert config.redact(None) == "<unset>"


def test_redact_empty_string_is_unset():
    assert config.redact("") == "<unset>"


def test_redact_short_secret_is_fully_masked():
    assert config.redact("abc") == "***"


def test_redact_never_contains_the_middle_of_the_secret():
    secret = "rzp_test_abcdefghijklmnop"
    redacted = config.redact(secret)
    assert redacted != secret
    assert "abcdefghijklmnop" not in redacted
    # Still recognisable enough to be useful in a log line -- first 4,
    # last 2, everything else masked.
    assert redacted.startswith(secret[:4])
    assert redacted.endswith(secret[-2:])


def test_validate_razorpay_key_id_accepts_none():
    config._validate_razorpay_key_id(None)  # must not raise


def test_validate_razorpay_key_id_accepts_test_key():
    config._validate_razorpay_key_id("rzp_test_abc123")  # must not raise


def test_validate_razorpay_key_id_rejects_live_key():
    with pytest.raises(config.ConfigError, match="rzp_test_"):
        config._validate_razorpay_key_id("rzp_live_abc123")


def test_validate_razorpay_key_id_rejects_garbage():
    with pytest.raises(config.ConfigError):
        config._validate_razorpay_key_id("not-a-razorpay-key-at-all")


def test_validate_razorpay_key_id_error_never_contains_the_raw_key():
    live_key = "rzp_live_supersecretvalue123"
    try:
        config._validate_razorpay_key_id(live_key)
    except config.ConfigError as exc:
        assert live_key not in str(exc)


def _run(code: str, *, env_overrides: dict) -> subprocess.CompletedProcess:
    env = dict(**os.environ)
    env["PYTHONPATH"] = SRC_PATH
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30
    )


def test_process_refuses_to_start_with_a_live_razorpay_key():
    """The real, end-to-end version of the above: importing darwaza.config
    in a fresh process with a live-looking key set must fail the import
    itself -- this is what "at startup, not at the moment of payment"
    actually means, proven across a real process boundary rather than
    just against the pure validation function."""
    result = _run(
        "import darwaza.config",
        env_overrides={"RAZORPAY_KEY_ID": "rzp_live_abc123", "RAZORPAY_KEY_SECRET": "shh"},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "rzp_test_" in result.stderr


def test_process_starts_fine_with_a_test_razorpay_key():
    result = _run(
        "import darwaza.config; print('ok')",
        env_overrides={"RAZORPAY_KEY_ID": "rzp_test_abc123", "RAZORPAY_KEY_SECRET": "shh"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok" in result.stdout


def test_process_starts_fine_with_no_razorpay_key_configured():
    env_overrides = {}
    env = dict(**os.environ)
    env.pop("RAZORPAY_KEY_ID", None)
    env.pop("RAZORPAY_KEY_SECRET", None)
    env["PYTHONPATH"] = SRC_PATH
    result = subprocess.run(
        [sys.executable, "-c", "import darwaza.config; print('ok')"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok" in result.stdout
