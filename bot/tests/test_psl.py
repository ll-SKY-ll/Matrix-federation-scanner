"""Tests for the public suffix list (csreg_scanner/psl.py).

Two fail-safe-relevant things live here:
  * PSLHolder.adopt MONOTONICITY -- refuses an older-or-equal list, so a stale
    mirror / rolled-back publish / replayed cache can't walk the fleet backwards
    past the version floor. This is where the PSL floor's safety actually lives.
  * the unknown-TLD fail-safe in etld1 -- a wholly unknown TLD makes the host
    its own bucket (matched=False), which the ban cap treats conservatively.

parse_psl_version is the anti-lexical-bug parser (same discipline as
parse_bot_version): parsed to a datetime, rejects int/bool, tolerant of pasted
header lines.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from csreg_scanner.psl import (
    PSLHolder,
    PublicSuffixList,
    parse_psl_version,
)

# A small hand-built list exercising all rule kinds. VERSION header present so
# it is orderable / adoptable.
_LIST = (
    "// VERSION: 2026-07-25_14-20-03_UTC\n"
    "// COMMIT: abc123\n"
    "com\n"
    "co.uk\n"
    "*.ck\n"       # wildcard
    "!www.ck\n"    # exception overriding the wildcard
    "github.io\n"  # PRIVATE-section style
)


def _psl(text=_LIST, source="test"):
    return PublicSuffixList(text, source=source)


def _list_with_version(stamp):
    return PublicSuffixList(f"// VERSION: {stamp}\ncom\n", source="v")


# --- etld1 algorithm --------------------------------------------------------


def test_etld1_simple():
    assert _psl().etld1("a.b.example.co.uk") == ("example.co.uk", True)


def test_etld1_private_section():
    """PRIVATE-section rules are honored (both sections are parsed)."""
    assert _psl().etld1("foo.github.io") == ("foo.github.io", True)


def test_etld1_wildcard_and_exception():
    """*.ck makes www.www.ck -> www.ck; the !www.ck exception is applied too."""
    etld1, matched = _psl().etld1("www.www.ck")
    assert matched is True
    assert etld1 == "www.ck"


def test_etld1_unknown_tld_fail_safe():
    """A wholly unknown TLD -> (host, False): its own bucket, conservatively.

    matched=False is the fail-safe path -- the cap counts the host as its own
    eTLD+1 rather than grouping it, and the caller emits the psl_unknown_tld
    tripwire. Never raises, never guesses a grouping.
    """
    etld1, matched = _psl().etld1("host.some-novel-tld")
    assert matched is False
    assert etld1 == "host.some-novel-tld"


# --- parse_psl_version ------------------------------------------------------


def test_parse_version_plain_stamp():
    dt = parse_psl_version("2026-07-25_14-20-03_UTC")
    assert dt == datetime(2026, 7, 25, 14, 20, 3, tzinfo=timezone.utc)


def test_parse_version_tolerates_pasted_header():
    """Operator workflow is copy-paste from the .dat, so header forms are ok."""
    a = parse_psl_version("// VERSION: 2026-07-25_14-20-03_UTC")
    b = parse_psl_version("VERSION: 2026-07-25_14-20-03_UTC")
    c = parse_psl_version("2026-07-25_14-20-03_UTC")
    assert a == b == c


def test_parse_version_rejects_non_string_scalars():
    """A YAML-bare int/bool must raise, so a typo'd min_psl_version is caught at
    config-apply time rather than comparing wrong."""
    with pytest.raises((ValueError, TypeError)):
        parse_psl_version(123)
    with pytest.raises((ValueError, TypeError)):
        parse_psl_version(True)


def test_parse_version_rejects_garbage():
    with pytest.raises(ValueError):
        parse_psl_version("not-a-stamp")


# --- PSLHolder.adopt monotonicity (the downgrade guard) --------------------


def test_adopt_newer_replaces():
    """A strictly newer list is adopted."""
    holder = PSLHolder(_list_with_version("2026-07-01_00-00-00_UTC"))
    newer = _list_with_version("2026-08-01_00-00-00_UTC")
    assert holder.adopt(newer) is True
    assert holder.current is newer


def test_adopt_older_refused_the_downgrade_guard():
    """THE downgrade guard: an older list is REFUSED.

    A stale mirror / rolled-back publish / replayed cached blob must not be able
    to walk the active list backwards -- that is what would let a bot slip below
    the min_psl_version floor. Monotonicity here is the enforcement.
    """
    current = _list_with_version("2026-07-01_00-00-00_UTC")
    holder = PSLHolder(current)
    older = _list_with_version("2026-01-01_00-00-00_UTC")
    assert holder.adopt(older) is False
    assert holder.current is current       # unchanged


def test_adopt_equal_refused():
    """An equal-version list is refused too (strictly newer required)."""
    current = _list_with_version("2026-07-01_00-00-00_UTC")
    holder = PSLHolder(current)
    same = _list_with_version("2026-07-01_00-00-00_UTC")
    assert holder.adopt(same) is False


def test_adopt_versionless_candidate_refused():
    """A candidate with no parseable VERSION cannot be ordered -> refused.

    An unversioned list can't be proven newer, so it must never replace a
    working one (it could be anything).
    """
    holder = PSLHolder(_list_with_version("2026-07-01_00-00-00_UTC"))
    nover = PublicSuffixList("com\n", source="nover")   # no VERSION header
    assert holder.adopt(nover) is False


def test_adopt_from_empty_accepts_any_versioned():
    """With no current list, any versioned candidate is adopted (nothing to
    downgrade from)."""
    holder = PSLHolder(None)
    cand = _list_with_version("2026-01-01_00-00-00_UTC")
    assert holder.adopt(cand) is True
    assert holder.current is cand
