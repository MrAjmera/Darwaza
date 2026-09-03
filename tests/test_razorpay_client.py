"""Unit test for the Razorpay client's fail-loudly-without-keys behavior.

No live Razorpay call is exercised here — that requires real test-mode
keys the user supplies themselves (see README). This only proves the
client refuses to silently no-op when unconfigured.
"""

from __future__ import annotations

import pytest

from darwaza import razorpay_client


def test_raises_without_keys(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("RAZORPAY_KEY_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="RAZORPAY_KEY_ID"):
        razorpay_client.create_order(100.0)
