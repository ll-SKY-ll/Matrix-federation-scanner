"""Shared pytest fixtures and import wiring.

Two jobs:

1. Import wiring. ``csreg_scanner/__init__.py`` does ``from .bot import
   CSRegScanner``, and ``bot.py`` pulls in maubot's plugin runtime -- so
   ``import csreg_scanner`` drags in the whole plugin stack and fails on a bare
   runner. The tests deliberately import *submodules* directly
   (``csreg_scanner.util``, ``csreg_scanner.psl``, ...), which do NOT trigger the
   package __init__'s bot import. We only need the package's parent dir on
   sys.path for that to resolve; this file lives in ``bot/tests`` and the package
   is ``bot/csreg_scanner``, so the parent we add is ``bot``.

2. The DB fixture. ``db.py`` is built on mautrix's async_db abstraction, which
   speaks both SQLite and Postgres behind one interface. So the DB tests
   parametrize over both backends:
     * sqlite  -- always runs, in-memory, no service, no network.
     * postgres -- runs only when TEST_POSTGRES_DSN is set (a dedicated
       throwaway db + role); skipped otherwise so local runs stay green.

   TEST_POSTGRES_DSN (not the fixed service-container vars) is the knob because
   the Postgres here is a long-lived instance in the LXC, addressed by DSN.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

# --- import wiring ----------------------------------------------------------
_BOT_DIR = Path(__file__).resolve().parent.parent  # .../bot
if str(_BOT_DIR) not in sys.path:
    sys.path.insert(0, str(_BOT_DIR))


# --- DB backend parametrization ---------------------------------------------
# Env var, not a fixed service-container name: the test Postgres is a persistent
# LXC instance reached over a DSN (see conftest docstring).
_PG_DSN = os.environ.get("TEST_POSTGRES_DSN")

_BACKENDS = ["sqlite"]
if _PG_DSN:
    _BACKENDS.append("postgres")


@pytest.fixture(params=_BACKENDS)
def db_backend(request):
    """The backend id under test. 'postgres' is present only when a DSN is set."""
    return request.param


@pytest_asyncio.fixture
async def database(db_backend, tmp_path):
    """A started mautrix Database with csreg_scanner's UpgradeTable applied.

    Each test gets a fresh, isolated database:
      * sqlite   -> a private file:: in-memory db, torn down with the connection.
      * postgres -> the DSN's db, wiped to a clean schema at setup so a crashed
        prior run can't leak rows into this one. This is why the DSN MUST point
        at a dedicated throwaway db -- setup drops every table in ``public``.

    The schema is created by running csreg_scanner.db's own UpgradeTable, so the
    tests exercise the real migrations (v1..v5), not a hand-rolled DDL copy that
    could drift from production.
    """
    from mautrix.util.async_db import Database

    from csreg_scanner.db import upgrade_table

    if db_backend == "sqlite":
        # File-backed db in pytest's per-test tmp_path, NOT an in-memory URI.
        # Why not in-memory: mautrix's aiosqlite backend takes url.path verbatim
        # and refuses it unless the *containing directory* is writable. A
        # ``sqlite:///file:<name>?mode=memory&...`` URL yields url.path
        # "/file:<name>", so mautrix probes "/" for writability and fails on any
        # runner not running as root ("unable to open database file"). A plain
        # filesystem path under tmp_path sidesteps mautrix's URI parsing
        # entirely. tmp_path is unique per test and auto-removed, so this is just
        # as isolated as a per-test in-memory db was meant to be, and it
        # persists across mautrix's pooled acquires for free (it's a real file).
        db = Database.create(
            f"sqlite:{tmp_path / 'test.db'}",
            upgrade_table=upgrade_table,
        )
        await db.start()
        try:
            yield db
        finally:
            await db.stop()
        return

    # postgres: wipe to a clean public schema before applying migrations, so
    # leftover state from an interrupted run cannot bleed across tests.
    db = Database.create(_PG_DSN, upgrade_table=upgrade_table)
    # Reset schema on the raw connection BEFORE start() runs the upgrade table,
    # otherwise the UpgradeTable sees existing version metadata and no-ops.
    import asyncpg

    reset = await asyncpg.connect(_PG_DSN)
    try:
        await reset.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    finally:
        await reset.close()

    await db.start()
    try:
        yield db
    finally:
        await db.stop()

# ===========================================================================
# Shared fakes for the policy layer (test_policy.py).
# ===========================================================================
#
# PolicyManager talks to two collaborators we don't want real in a unit test:
#   * a mautrix Client -- only four members are touched: mxid, get_state,
#     get_state_event, send_state_event. The fake RECORDS send_state_event calls
#     instead of hitting a homeserver, so "did the bot write?" becomes "was the
#     recorder called?" -- the whole point of the fake-client technique.
#   * a PSLHolder -> PublicSuffixList -- policy reads holder.current and, on the
#     list, .version / .version_raw / .source / .etld1(). The fakes model just
#     that surface.
#
# These live here so test_policy.py stays about behavior, not scaffolding, and
# so the same fakes back the reconcile, cleanup, and PSL-floor tests uniformly.

import logging as _logging

from mautrix.errors import MLimitExceeded


class FakeClient:
    """Minimal stand-in for mautrix.client.Client.

    send_state_event appends (state_key, content) to `.writes` instead of
    sending. Tests assert on `.writes` to prove a write did or did not happen --
    the fail-safe question for the whole policy layer. get_state returns a
    scripted list (default empty); get_state_event returns scripted content or
    raises a scripted exception (to drive the halt-on-unreadable paths).
    """

    def __init__(self, mxid="@bot:example.org", state=None,
                 state_event=None, state_event_exc=None,
                 send_exc=None, send_exc_times=0):
        self.mxid = mxid
        self.writes = []                    # recorded (state_key, content)
        self._state = state or []
        self._state_event = state_event or {}
        self._state_event_exc = state_event_exc
        # Optional: raise `send_exc` for the first `send_exc_times` sends, to
        # exercise the 429 retry loop without a real homeserver.
        self._send_exc = send_exc
        self._send_exc_times = send_exc_times
        self._send_calls = 0

    async def get_state(self, room_id):
        if isinstance(self._state, Exception):
            raise self._state
        return self._state

    async def get_state_event(self, room_id, event_type, state_key):
        if self._state_event_exc is not None:
            raise self._state_event_exc
        return self._state_event

    async def send_state_event(self, room_id, event_type, content, state_key):
        self._send_calls += 1
        if self._send_exc is not None and self._send_calls <= self._send_exc_times:
            raise self._send_exc
        self.writes.append((state_key, dict(content)))


class FakePSL:
    """Stand-in for PublicSuffixList.

    version / version_raw / source model the header stamp used by the floor.
    etld1(host) returns (etld1, matched); the fake collapses a host to its last
    two labels and reports matched=True unless the host is in `unknown_tlds`.
    """

    def __init__(self, version=None, version_raw=None, source="test",
                 unknown_tlds=frozenset()):
        self.version = version              # a datetime or None
        self.version_raw = version_raw      # the raw stamp string or None
        self.source = source
        self._unknown = set(unknown_tlds)

    def etld1(self, host):
        if host in self._unknown:
            return host, False
        labels = host.split(".")
        if len(labels) >= 2:
            return ".".join(labels[-2:]), True
        return host, True


class FakeHolder:
    """Stand-in for PSLHolder: policy only reads `.current`."""

    def __init__(self, current=None):
        self.current = current


def make_policy(**overrides):
    """Construct a PolicyManager wired to fakes, with sensible test defaults.

    Overrides let a test swap in a specific client / psl_holder / own_version /
    domain_statuses without restating the whole constructor. Returns
    (manager, client) so tests can assert on client.writes directly.
    """
    from csreg_scanner.policy import PolicyManager

    client = overrides.pop("client", None) or FakeClient()
    ds = overrides.pop("domain_statuses", None)
    if ds is None:
        async def ds(domain):
            return []

    kwargs = dict(
        client=client,
        room_id="!room:example.org",
        auto_config_type="com.example.csreg.autoconfig",
        max_writes_per_second=0,        # 0 disables the throttle in tests
        known_statuses=frozenset(
            {"dangerously_open", "open", "oauth", "closed", "unknown"}
        ),
        log=_logging.getLogger("test_policy"),
        domain_statuses=ds,
        own_version="0.2.0",
    )
    kwargs.update(overrides)
    return PolicyManager(**kwargs), client


# ===========================================================================
# Fake aiohttp session for classifier tests (test_regcheck.py).
# ===========================================================================
#
# RegistrationChecker.classify walks HTTP responses through pure classifier
# functions. To test the RESPONSE-MAPPING layer (which status/body becomes which
# signal) without a network, we script responses per-URL-substring. Each scripted
# response models just what read_json_capped + the checker read: .status and a
# streaming body.

import json as _json


class _FakeContent:
    """Models resp.content.iter_chunked() over a fixed body."""

    def __init__(self, body_bytes):
        self._body = body_bytes

    async def iter_chunked(self, n):
        # One chunk is fine for test bodies (well under the cap).
        if self._body:
            yield self._body


class FakeResponse:
    """A scripted aiohttp response usable as an async context manager.

    status: the HTTP status. body: a JSON-serializable object (or a raw
    bytes/str for malformed-body tests, or None for an empty body).
    """

    def __init__(self, status=200, body=None, raw=None):
        self.status = status
        if raw is not None:
            self._bytes = raw if isinstance(raw, bytes) else raw.encode()
        elif body is None:
            self._bytes = b""
        else:
            self._bytes = _json.dumps(body).encode()
        self.content = _FakeContent(self._bytes)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Scripts responses by URL substring for get() and post().

    routes: list of (substring, FakeResponse-or-callable-or-Exception). The
    first substring found in the URL wins. A callable is invoked to produce the
    response (so a route can vary per call); an Exception instance is raised (to
    model aiohttp.ClientError / timeout paths). Unmatched URLs default to a 404.
    """

    def __init__(self, get_routes=None, post_routes=None):
        self._get = get_routes or []
        self._post = post_routes or []

    def _match(self, routes, url):
        for substr, resp in routes:
            if substr in url:
                return resp
        return FakeResponse(status=404)

    def _resolve(self, resp):
        if isinstance(resp, Exception):
            raise resp
        if callable(resp) and not isinstance(resp, FakeResponse):
            return resp()
        return resp

    def get(self, url, **kwargs):
        return self._resolve(self._match(self._get, url))

    def post(self, url, **kwargs):
        return self._resolve(self._match(self._post, url))
