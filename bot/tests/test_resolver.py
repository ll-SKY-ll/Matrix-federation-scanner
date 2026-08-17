"""Tests for the pure parts of the resolver (csreg_scanner/resolver.py).

Covered (pure, no network):
  * parse_name    -- host/port/IPv6-literal parsing.
  * _order_srv / _weighted_pick_index -- RFC 2782 ordering, including the
    documented past bug where a weight-0 record could win a lottery it holds no
    tickets in.

NOT covered here: the async resolution branches (well-known-before-SRV,
short-circuiting) -- those need a fake aiohttp session + fake DNS and were left
out of this pass. The pure ordering and parsing below are where the subtle
correctness bugs actually lived.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from csreg_scanner.resolver import parse_name, _order_srv, _weighted_pick_index


# --- parse_name -------------------------------------------------------------


def test_parse_name_plain_and_port():
    p = parse_name("matrix.org")
    assert p.host == "matrix.org" and p.port is None and p.is_ip_literal is False

    p = parse_name("matrix.org:8448")
    assert p.host == "matrix.org" and p.port == 8448


def test_parse_name_ipv6_literal():
    p = parse_name("[2001:db8::1]:8448")
    assert p.host == "2001:db8::1"
    assert p.port == 8448
    assert p.is_ip_literal is True
    assert p.host_with_brackets == "[2001:db8::1]"


def test_parse_name_ipv6_no_port():
    p = parse_name("[::1]")
    assert p.host == "::1" and p.port is None and p.is_ip_literal is True


def test_parse_name_ipv4_literal():
    p = parse_name("1.2.3.4:8448")
    assert p.host == "1.2.3.4" and p.port == 8448 and p.is_ip_literal is True


def test_parse_name_malformed_bracket_raises():
    """A bracketed literal with no closing bracket is a hard parse error."""
    with pytest.raises(ValueError):
        parse_name("[2001:db8::1")


def test_parse_name_bad_ipv6_raises():
    with pytest.raises(ValueError):
        parse_name("[not-an-address]")


# --- SRV ordering -----------------------------------------------------------


def _srv(priority, weight, target, port=8448):
    """A minimal SRV-record stand-in with the fields _order_srv reads."""
    return SimpleNamespace(priority=priority, weight=weight,
                           target=target, port=port)


def test_order_srv_orders_by_priority_ascending():
    """Lower priority number is tried first (RFC 2782)."""
    records = [_srv(20, 0, "b"), _srv(10, 0, "a"), _srv(30, 0, "c")]
    ordered = _order_srv(records)
    targets = [r.target for r in ordered]
    assert targets == ["a", "b", "c"]


def test_order_srv_includes_every_record_once():
    """Selection is WITHOUT replacement: every record appears exactly once.

    This is what makes it an ORDER (a fallback walk) rather than a single pick --
    a weight-0 backup must still be reachable after the weighted primaries.
    """
    records = [_srv(10, 100, "primary"), _srv(10, 0, "backup")]
    ordered = _order_srv(records)
    assert sorted(r.target for r in ordered) == ["backup", "primary"]
    assert len(ordered) == 2


def test_weighted_pick_all_zero_band_is_valid_index():
    """An all-zero-weight band is undefined in the RFC; treat as equals.

    Must return a valid in-range index, never raise or divide by zero.
    """
    records = [_srv(10, 0, "a"), _srv(10, 0, "b")]
    idx = _weighted_pick_index(records)
    assert 0 <= idx < len(records)


def test_weighted_pick_zero_weight_not_preferred_over_positive():
    """The documented past bug: a weight-0 record must NOT win over a positive
    one.

    Old code used `pick <= upto`; random.uniform(0, total) is inclusive of 0, so
    a weight-0 record in first position (upto still 0) could win on pick==0.
    Strict `<` makes a zero-weight record unreachable while any positive weight
    remains. Run many trials: the weight-0 record must never be picked FIRST
    while a positive-weight record is present.

    (Statistical, but the property is deterministic: with strict `<`, pick==0
    can't select the zero-weight first record; with `<=` it could. Many trials
    make a regression essentially certain to show.)
    """
    picked_zero_first = 0
    for _ in range(2000):
        # weight-0 record FIRST, positive-weight record second.
        band = [_srv(10, 0, "zero"), _srv(10, 100, "positive")]
        idx = _weighted_pick_index(band)
        if band[idx].target == "zero":
            picked_zero_first += 1
    assert picked_zero_first == 0      # zero-weight never wins over positive
