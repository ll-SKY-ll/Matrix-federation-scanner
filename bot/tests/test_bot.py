"""Tests for rescan rate calculation in bot.py (csreg_scanner/bot.py).

Scope: the STALENESS CALCULATION (_required_rate) and its fallback behavior when
`unknown` is not configured. These are the demand-math that drives the rescan
rate-meter -- getting the denominator wrong (or crashing on a missing key) would
either stall rescans or divide by zero on a live tick.

CSRegScanner is a maubot Plugin and can't be constructed without the framework,
but _required_rate is a pure method that only reads self._staleness. So it is
tested by calling the unbound method with a minimal synthetic `self` carrying
just that attribute -- no maubot runtime, no DB, no loop. This reaches into an
internal method deliberately: the arithmetic is the valuable, bug-prone part,
and it is pure, so testing it directly is honest and cheap.

The `unknown`-absent fallback is the specific thing pinned here: `unknown`
doubles as the default T for any unmapped status, so when it is absent the code
must fall back to _DEFAULT_STALENESS_SECONDS (86400) rather than crash or return
a zero denominator. A future "simplification" of the two-level .get() is exactly
the kind of change that could silently break this, which is why it is pinned.
"""

from __future__ import annotations

import logging

from csreg_scanner.bot import (
    CSRegScanner,
    _DEFAULT_STALENESS_SECONDS,
    _sanitize_staleness,
)


_LOG = logging.getLogger("test_bot")


# ===========================================================================
# _sanitize_staleness -- config validation for rescan.staleness_seconds.
# ===========================================================================
#
# Extracted from start() specifically so these branches are testable without a
# maubot Plugin runtime. Each rule drops a bad entry; the final check warns when
# `unknown` is unconfigured (because it silently becomes the default-T source).


def test_sanitize_keeps_valid_entries():
    """A clean {status: seconds} map survives intact."""
    out = _sanitize_staleness({"unknown": 3600, "closed": 7200}, _LOG)
    assert out == {"unknown": 3600, "closed": 7200}


def test_sanitize_drops_unknown_status_key():
    """A key not in KNOWN_STATUSES is dropped (typo / bad SQL guard).

    These keys are interpolated into a SQL CASE by db.most_overdue, so an
    unrecognised status must never survive into the map. Dropping it also
    surfaces a config typo instead of silently defaulting it.
    """
    out = _sanitize_staleness({"unknown": 3600, "bogus_status": 60}, _LOG)
    assert out == {"unknown": 3600}
    assert "bogus_status" not in out


def test_sanitize_drops_non_integer_value():
    """A non-integer T is dropped rather than crashing the sanitizer."""
    out = _sanitize_staleness({"unknown": "sixty"}, _LOG)
    assert out == {}


def test_sanitize_drops_non_positive_value():
    """T <= 0 is dropped (a zero/negative deadline is meaningless and would be a
    divide-by-zero in the rate math)."""
    out = _sanitize_staleness({"unknown": 0, "closed": -5}, _LOG)
    assert out == {}


def test_sanitize_none_and_empty_config():
    """None or empty config yields an empty map, no crash."""
    assert _sanitize_staleness(None, _LOG) == {}
    assert _sanitize_staleness({}, _LOG) == {}


def test_sanitize_warns_when_unknown_unset(caplog):
    """The requested warning: no `unknown` entry emits staleness_unknown_unset.

    `unknown` doubles as the default T for unmapped statuses, so its absence
    silently makes that default the hardcoded 86400s. The operator's only signal
    is this one-time config-load warning; assert it fires and carries the
    structured alarm key so it's alertable.
    """
    with caplog.at_level(logging.WARNING):
        _sanitize_staleness({"closed": 7200}, _LOG)   # no 'unknown'
    matching = [r for r in caplog.records
                if getattr(r, "csreg_alarm", None) == "staleness_unknown_unset"]
    assert len(matching) == 1
    assert "unknown" in matching[0].message


def test_sanitize_no_warning_when_unknown_set(caplog):
    """The complement: with `unknown` configured, no unset-warning fires.

    Guards against the warning becoming unconditional noise -- it must fire only
    when unknown is genuinely absent.
    """
    with caplog.at_level(logging.WARNING):
        _sanitize_staleness({"unknown": 3600}, _LOG)
    assert not any(getattr(r, "csreg_alarm", None) == "staleness_unknown_unset"
                   for r in caplog.records)


def test_sanitize_unknown_dropped_as_invalid_still_warns(caplog):
    """Subtle: if `unknown` is PRESENT but INVALID (dropped), the unset-warning
    still fires -- because it's absent from the RESULT, which is what matters.

    An operator who wrote `unknown: 0` (dropped as non-positive) has effectively
    not configured a usable default, so they should get the same heads-up. This
    pins that the warning keys off the sanitized result, not the raw input.
    """
    with caplog.at_level(logging.WARNING):
        out = _sanitize_staleness({"unknown": 0}, _LOG)   # present but invalid
    assert out == {}
    assert any(getattr(r, "csreg_alarm", None) == "staleness_unknown_unset"
               for r in caplog.records)


class _FakeSelf:
    """Minimal stand-in carrying only what _required_rate reads."""

    def __init__(self, staleness):
        self._staleness = staleness


def _required_rate(staleness, buckets):
    """Call the pure method with a synthetic self (no maubot runtime)."""
    return CSRegScanner._required_rate(_FakeSelf(staleness), buckets)


# --- baseline: the calculation itself --------------------------------------


def test_required_rate_sums_demand():
    """Demand is sum(N_bucket / T_bucket) across buckets."""
    rate = _required_rate(
        {"unknown": 100, "closed": 200}, {"unknown": 10, "closed": 10}
    )
    assert rate == 10 / 100 + 10 / 200        # 0.15


def test_required_rate_empty_buckets_is_zero():
    """No servers -> no demand."""
    assert _required_rate({"unknown": 100}, {}) == 0.0


def test_required_rate_uses_unknown_as_default_for_unmapped():
    """A bucket status with no own T uses `unknown`'s T as the default.

    Here dangerously_open has no explicit entry, so it borrows unknown's 100.
    """
    rate = _required_rate({"unknown": 100}, {"dangerously_open": 10})
    assert rate == 10 / 100


# --- the unknown-absent fallback -------------------------------------------


def test_required_rate_default_when_unknown_absent():
    """With `unknown` UNSET, an unmapped bucket falls back to the 86400 default.

    This is the two-level fallback: default_t = _staleness.get("unknown", 86400)
    fires the hardcoded default because unknown is absent, then the unmapped
    bucket uses that default. Pinned against _DEFAULT_STALENESS_SECONDS (not a
    bare literal) so the test tracks the constant if it ever changes.
    """
    rate = _required_rate({"closed": 200}, {"dangerously_open": 10})
    assert rate == 10 / _DEFAULT_STALENESS_SECONDS


def test_required_rate_unknown_bucket_uses_default_when_unknown_unset():
    """An `unknown` BUCKET with no configured `unknown` T uses the 86400 default.

    Distinct from the above: here the bucket status IS 'unknown' but there is no
    staleness entry for it, so it too falls to the default rather than raising a
    KeyError.
    """
    rate = _required_rate({"closed": 200}, {"unknown": 10})
    assert rate == 10 / _DEFAULT_STALENESS_SECONDS


def test_required_rate_unknown_absent_does_not_crash():
    """The safety pin: `unknown` absent must never KeyError or divide by zero.

    Mixed buckets, empty staleness map entirely -> every status falls to the
    default. The explicit point is that a missing `unknown` produces a finite,
    positive denominator for every term, never an exception.
    """
    rate = _required_rate({}, {"unknown": 5, "closed": 5, "open": 5})
    assert rate == 15 / _DEFAULT_STALENESS_SECONDS
    assert rate > 0


def test_required_rate_unknown_absent_keeps_configured_status_T():
    """A configured status keeps ITS OWN T even when `unknown` is absent.

    Proves the fallback only affects UNMAPPED statuses -- it must not clobber a
    status that has its own explicit T. closed uses 200; the unmapped
    dangerously_open uses the 86400 default. Both terms coexist correctly.
    """
    rate = _required_rate({"closed": 200}, {"closed": 10, "dangerously_open": 10})
    assert rate == 10 / 200 + 10 / _DEFAULT_STALENESS_SECONDS
