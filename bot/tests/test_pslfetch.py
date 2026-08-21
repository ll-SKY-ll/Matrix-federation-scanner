"""Tests for the PSL fetch validation gauntlet + jitter (csreg_scanner).

The gauntlet (validate_psl_text, in psl.py) is the fail-safe that makes "a bad
list is worse than an old one" true: a truncated / section-filtered / mostly-
empty body must be REFUSED so the caller keeps its working list rather than
adopting a broken one that silently changes bucketing for every entity. These
are the refusal tests -- the valuable direction.

jittered_interval (pslfetch.py) is pure: spreads fleet refetches so they don't
stampede publicsuffix.org in lockstep.
"""

from __future__ import annotations

import pytest

from csreg_scanner.psl import PSLValidationError, validate_psl_text
from csreg_scanner.pslfetch import jittered_interval

_MARKERS = (
    "// ===BEGIN ICANN DOMAINS===\n"
    "// ===BEGIN PRIVATE DOMAINS===\n"
)


def _body(version="2026-07-25_14-20-03_UTC", rules="com\n", markers=True):
    head = f"// VERSION: {version}\n"
    mk = _MARKERS if markers else ""
    return head + mk + rules


def test_gauntlet_rejects_missing_section_markers():
    """A body lacking the ICANN/PRIVATE markers (truncated/filtered) is refused."""
    with pytest.raises(PSLValidationError):
        validate_psl_text(_body(markers=False), source="t")


def test_gauntlet_rejects_missing_version():
    """No VERSION stamp -> refused (unorderable against the floor, likely an
    error page)."""
    body = _MARKERS + "com\n"          # no // VERSION line
    with pytest.raises(PSLValidationError):
        validate_psl_text(body, source="t")


def test_gauntlet_sentinel_catches_gutted_body():
    """A truncated body that DROPPED real suffix rules is refused by a sentinel.

    This is now the load-bearing "catches a broken body" check (the absolute
    rule-count floor was removed -- see the note in the module docstring and
    test_gauntlet_small_but_correct_list_passes below). Here the body keeps the
    section markers and a valid VERSION but has had the PRIVATE-section rule
    (github.io) truncated away, so the foo.github.io sentinel fails to resolve.
    That is exactly the "structurally present, substantively broken" shape the
    sentinels exist to catch.
    """
    gutted = _body(rules="com\nco.uk\n*.ck\n!www.ck\n")   # github.io removed
    with pytest.raises(PSLValidationError, match="sentinel"):
        validate_psl_text(gutted, source="t")


def test_gauntlet_small_but_correct_list_passes():
    """A SMALL but correct list PASSES -- the deliberate behavior after removing
    the absolute rule-count floor.

    This documents the intended change: an absolute count floor would reject a
    legitimately-shrunk list and force a fleet-wide code change to accept the
    valid new list (a guard failing closed on good data). So a tiny list that
    resolves every sentinel correctly is accepted. If a future change
    reintroduces a hard count floor, THIS test will fail and force a conversation
    about the staleness liability that motivated the removal.

    (The realistic bad-list scenario -- a subtly-wrong but full-size list -- is
    handled by min_psl_version, not the gauntlet: bump the floor, the fleet
    refetches the corrected list.)
    """
    tiny_correct = _body(rules="com\nco.uk\n*.ck\n!www.ck\ngithub.io\n")
    psl = validate_psl_text(tiny_correct, source="t")   # must NOT raise
    assert psl.version_raw == "2026-07-25_14-20-03_UTC"


def test_gauntlet_rejects_broken_sentinels():
    """Even a big-enough body is refused if the sentinels don't resolve right.

    The sentinel check is the only one that verifies the PARSE actually works,
    not just that the bytes look plausible. Build a body that clears the rule
    floor with junk rules but lacks the real suffix rules -> sentinels fail.
    """
    junk = "".join(f"junk{i}.invalid\n" for i in range(7000))
    with pytest.raises(PSLValidationError):
        validate_psl_text(_body(rules=junk), source="t")


def test_jittered_interval_stays_in_band():
    """Jitter perturbs the interval within a bounded band, never wild or negative."""
    for _ in range(1000):
        v = jittered_interval(100.0)
        assert 50.0 <= v <= 150.0      # generous band; never negative/zero-ish
