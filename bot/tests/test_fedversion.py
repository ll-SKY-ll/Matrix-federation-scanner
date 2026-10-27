"""Tests for the federation-version interpreter (csreg_scanner/fedversion.py).

Pure part: _interpret(body) applies the authoritative-answer contract that
drives db.record_scan's overwrite-vs-preserve (tested from the DB side in
test_db.py). The subtlety worth pinning: BOTH server.name and server.version
keys must be PRESENT (membership) for authoritative=True, but their VALUES may
be null -- an authoritative null-report (server truthfully reports null) still
overwrites, while a missing key is non-authoritative and preserves prior state.
"""

from __future__ import annotations

import logging

import aiohttp

from csreg_scanner.fedversion import FederationVersionProbe, _truncate_field
from csreg_scanner.resolver import FederationTarget, ResolutionMethod

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


# --- TLS: cert name passthrough + connector posture -------------------------


def _target(host, port, host_header, tls_name, method=ResolutionMethod.SRV):
    return FederationTarget(
        host=host,
        port=port,
        host_header=host_header,
        tls_server_name=tls_name,
        resolution_method=method,
    )


class _StubResolver:
    def __init__(self, targets):
        self._targets = targets

    async def resolve_candidates(self, server_name):
        return self._targets


class _Resp:
    status = 404

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _RecordingGet:
    """Stands in for session.get: records kwargs, fails the first `fail` calls
    with a connection error, answers 404 after that (ends the walk)."""

    def __init__(self, fail=0):
        self.calls = []
        self._fail = fail

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if len(self.calls) <= self._fail:
            raise aiohttp.ClientConnectionError("cert verify failed")
        return _Resp()


async def _probe_with(targets, get):
    probe = FederationVersionProbe(client=None, log=logging.getLogger("t"))
    probe._resolver = _StubResolver(targets)
    real_client = probe._probe_client
    probe._probe_client = type("C", (), {"get": get})()
    try:
        return await probe.probe("example.org")
    finally:
        await real_client.close()


async def test_probe_connector_verifies_and_disables_keepalive():
    probe = FederationVersionProbe(client=None, log=logging.getLogger("t"))
    try:
        conn = probe._probe_client.connector
        assert conn.force_close is True
        assert conn._ssl is not False
    finally:
        await probe.aclose()


async def test_server_hostname_is_tls_server_name_not_connect_host():
    get = _RecordingGet()
    await _probe_with(
        [_target("srv.host.net", 443, "example.org", "example.org")], get,
    )
    url, kwargs = get.calls[0]
    assert url == "https://srv.host.net:443/_matrix/federation/v1/version"
    assert kwargs["server_hostname"] == "example.org"
    assert kwargs["headers"]["Host"] == "example.org"


async def test_ip_literal_passes_none_server_hostname():
    get = _RecordingGet()
    await _probe_with(
        [_target("2001:db8::1", 8448, "[2001:db8::1]", None,
                 ResolutionMethod.IP_LITERAL)], get,
    )
    assert get.calls[0][1]["server_hostname"] is None


async def test_tls_failure_advances_walk_with_per_candidate_name():
    get = _RecordingGet(fail=1)
    result = await _probe_with(
        [
            _target("a.host.net", 8448, "example.org", "example.org"),
            _target("b.host.net", 8448, "example.org", "example.org"),
        ],
        get,
    )
    assert len(get.calls) == 2
    assert all(kw["server_hostname"] == "example.org" for _, kw in get.calls)
    assert result.authoritative is False
