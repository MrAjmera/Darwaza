"""One Razorpay test-mode order, created after a human-approved
NEEDS_HUMAN request (or a deterministic ALLOW). See DECISIONS.md #7 for
what this honestly does and does not prove.

Requires RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET (test-mode keys from
the Razorpay dashboard: Settings -> API Keys) as environment variables.
If they aren't set, create_order() raises immediately rather than
pretending to succeed — a demo step that silently no-ops on a missing
key is worse than one that fails loudly and says why.
"""

from __future__ import annotations

import os


def create_order(amount_rupees: float, *, currency: str = "INR", receipt: str | None = None) -> dict:
    """Create a Razorpay test-mode order for `amount_rupees`, configured
    to auto-capture once a payment is made against it.

    IMPORTANT — what this does NOT do: it does not itself move money or
    simulate a card/UPI payment. Actually completing a payment against
    this order requires Razorpay's Checkout (a real frontend flow, out of
    scope here — Darwaza is the authorization gateway, not a checkout
    UI, see DECISIONS.md's problem statement) or Razorpay's test-mode
    payment-simulation API called separately. "Order create + capture"
    in the build plan means: a real order exists in Razorpay's test
    environment, correctly configured, proving the authorization
    decision actually reaches a real payment processor — not that a full
    payment round-trip happened headlessly.
    """
    key_id = os.environ.get("RAZORPAY_KEY_ID")
    key_secret = os.environ.get("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise RuntimeError(
            "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. Get test-mode "
            "keys from the Razorpay dashboard (Settings -> API Keys) and set "
            "them as environment variables before executing a transaction."
        )

    import razorpay  # local import: keep this an optional dependency

    client = razorpay.Client(auth=(key_id, key_secret))

    amount_paise = int(round(amount_rupees * 100))  # Razorpay amounts are in paise
    return client.order.create(
        {
            "amount": amount_paise,
            "currency": currency,
            "receipt": receipt,
            "payment_capture": 1,
        }
    )
