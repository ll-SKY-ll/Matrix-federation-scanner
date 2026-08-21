"""Tests for the federation-version interpreter (csreg_scanner/fedversion.py).

Pure part: _interpret(body) applies the authoritative-answer contract that
drives db.record_scan's overwrite-vs-preserve (tested from the DB side in
test_db.py). The subtlety worth pinning: BOTH server.name and server.version
keys must be PRESENT (membership) for authoritative=True, but their VALUES may
be null -- an authoritative null-report (server truthfully reports null) still
overwrites, while a missing key is non-authoritative and preserves prior state.
"""

from __future__ import annotations

from csreg_scanner.fedversion import FederationVersionProbe, _truncate_field

_interpret = FederationVersionProbe._interpret


def test_interpret_full_answer_authoritative():
    v = _interpret({"server": {"name": "Synapse", "version": "1.96.0"}})
    assert v.authoritative is True
    assert v.name == "Synapse"
    assert v.version == "1.96.0"


def test_interpret_present_but_null_is_authoritative():
    """Both keys present with null values -> authoritative (server said null).

    This is the case that must OVERWRITE a stored version down to null (the
    reason db.py uses a CASE, not COALESCE). Present-and-null != absent.
    """
    v = _interpret({"server": {"name": None, "version": None}})
    assert v.authoritative is True
    assert v.name is None
    assert v.version is None


def test_interpret_missing_a_key_is_non_authoritative():
    """A key MISSING (not null) -> non-authoritative -> caller preserves prior.

    'name' present but 'version' absent is not a trustworthy full answer, so it
    must not overwrite. This is the membership-vs-value distinction.
    """
    v = _interpret({"server": {"name": "Synapse"}})
    assert v.authoritative is False


def test_interpret_no_server_key_non_authoritative():
    assert _interpret({"foo": 1}).authoritative is False


def test_interpret_non_dict_non_authoritative():
    """A non-dict body (parse junk) -> non-authoritative, never raises."""
    assert _interpret("not-a-dict").authoritative is False
    assert _interpret(None).authoritative is False


def test_truncate_caps_length():
    """Field values are capped (60 chars) so a hostile server can't store a
    giant string in the version column."""
    out = _truncate_field("x" * 200)
    assert out is not None and len(out) == 60


def test_truncate_non_string_is_none():
    assert _truncate_field(123) is None
    assert _truncate_field(None) is None
