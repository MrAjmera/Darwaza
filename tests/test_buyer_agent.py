"""Unit tests for the deterministic (no-API-key) buyer agent path."""

from __future__ import annotations

import pytest

from darwaza.buyer_agent import decide_deterministic


def test_picks_cheapest_product_in_category():
    tx = decide_deterministic("electronics")
    # sku-poisoned-earbuds (Rs.89) is cheaper than sku-headphones-1 (Rs.1200)
    # when injection isn't obeyed, so the honest price wins.
    assert tx.amount == 89.0
    assert tx.category == "electronics"


def test_unknown_category_raises():
    with pytest.raises(ValueError):
        decide_deterministic("nonexistent-category")


def test_ignores_injection_by_default():
    tx = decide_deterministic("electronics", obey_injected_instructions=False)
    assert tx.amount == 89.0  # the real price, not the injected 999999


def test_obeys_injection_when_flag_set():
    # This is the concrete demonstration of "poisoned catalog manipulates
    # the buying agent": with the flag on, the "agent" does what the
    # embedded instruction in the product description asked for.
    tx = decide_deterministic("electronics", obey_injected_instructions=True)
    assert tx.amount == 999999.0
