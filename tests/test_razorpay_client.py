"""Unit test for the Razorpay client's fail-loudly-without-keys behavior.

No live Razorpay call is exercised here — that requires real test-mode
keys the user supplies themselves (see README). This only proves the
client refuses to silently no-op when unconfigured.

As of Stage 5, create_order() reads its keys from config.py, which
resolves them from os.environ once at import time -- not per call. So
`monkeypatch.delenv(...)` (which only affects os.environ dynamically)
has no effect on what create_order() actually sees any more;
`monkeypatch.setattr(config, "RAZORPAY_KEY_ID", ...)` is what reaches
it, since razorpay_client.py does `from darwaza import config` and
reads `config.RAZORPAY_KEY_ID` at call time (an attribute lookup on the
live config module), not a name bound once at its own import time. See
config.py's module docstring for why every module keeps this pattern.
"""

from __future__ import annotations

import pytest

from darwaza import config, razorpay_client


def test_raises_without_keys(monkeypatch):
    monkeypatch.setattr(config, "RAZORPAY_KEY_ID", None)
    monkeypatch.setattr(config, "RAZORPAY_KEY_SECRET", None)

    with pytest.raises(RuntimeError, match="RAZORPAY_KEY_ID"):
        razorpay_client.create_order(100.0)
