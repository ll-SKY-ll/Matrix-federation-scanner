"""Ingress sources.

All sources implement one interface: `fetch() -> list[str]` ("yields domains").
The pipeline does not care which source produced a domain. Pull sources fetch
their full current list on their own clock; the webhook (push) is handled
directly in bot.py and feeds the same enqueue path.

Every source only ever ADDS to the queue; only the scanner drains it.
"""

from __future__ import annotations

import logging
import re
from typing import Protocol
from urllib.parse import urlsplit

import aiohttp

from .util import validate_server_name

try:
    import asyncpg
except ImportError:
    asyncpg = None 


# Weak safeguard to try to help people to NOT shoot themselves in the foot.
# The real safeguard is setting up the postgres user with the correct permissions
_SELECT_ONLY = re.compile(r"^\s*(?:WITH\b.+?\bSELECT\b|SELECT\b)", re.IGNORECASE | re.DOTALL)


def _is_select_only(query: str) -> bool:
    """True if `query` is a single read-only SELECT (optionally a CTE that
    resolves to SELECT). Rejects multiple statements (a `;` separating
    statements) and anything not starting in SELECT/WITH...SELECT."""
    q = query.strip()
    # Strip a single trailing semicolon (one statement, terminated) but reject
    # an internal one (statement stacking).
    if q.endswith(";"):
        q = q[:-1].rstrip()
    if ";" in q:
        return False
    return bool(_SELECT_ONLY.match(q))


class Source(Protocol):
    name: str

    async def fetch(self) -> list[str]:
        ...


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except Exception:  # noqa: BLE001 -- naming aid only, never load-bearing
        return url


class TextFileSource:
    """Pull whitespace-separated server names from a URL. Default/primary source
    any operator can put any logic behind the URL (e.g. cron dumping
    SELECT DISTINCT server_name to a file) without handing the bot DB creds.

    This is the ONLY source you can configure multiple of (sources.textfiles is
    a list). Each instance gets a name `textfile:<host>` so overlapping lists
    are distinguishable in the logs. Optional `headers` (e.g. bearer auth for a
    list fronted by proxy /etc) live in YAML config only and are never logged.
    """

    def __init__(
        self,
        url: str,
        http: aiohttp.ClientSession,
        log: logging.Logger,
        *,
        headers: dict[str, str] | None = None,
    ):
        self.url = url
        self.http = http
        self.log = log
        self.headers = dict(headers or {})
        self.name = f"textfile:{_host_of(url)}"

    async def fetch(self) -> list[str]:
        async with self.http.get(self.url, headers=self.headers or None) as resp:
            resp.raise_for_status()
            text = await resp.text()
        return text.split()


class PolicyListSource:
    """The policy list itself as a source. On a shared list, entries are
    contributed by MANY operators; feeding them back into the scan queue lets
    this bot independently re-verify domains it never discovered on its own --
    and a server that fixes its registration gets reconciled back out (the
    scanner result flows to the SAME policy room, so source and sink coincide;
    this loop is intentional and the policy layer's local-state no-op guard keeps
    it from spamming writes).

    No I/O: reads PolicyManager's already-maintained in-memory rule fold via
    scannable_entities(), which port-strips and drops glob patterns. Cheap enough
    to run on a short clock, but the fold only changes as fast as the policy room
    does, so a modest interval is plenty.
    """

    name = "policy_list"

    def __init__(self, policy: "PolicyProvider", log: logging.Logger):
        self.policy = policy
        self.log = log

    async def fetch(self) -> list[str]:
        return self.policy.scannable_entities()


class PolicyProvider(Protocol):
    def scannable_entities(self) -> list[str]:
        ...


class PostgresSource:
    """Foreign asyncpg connection the plugin manages itself (connect/pool/retry/
    shutdown), OUTSIDE maubot's managed DB lifecycle. MUST be pointed at a
    dedicated SELECT-only DB user scoped to one table -- that read-only role is
    the actual security boundary. DSN lives in YAML config, never any web-exposed
    surface.

    As an additional (non-authoritative) safeguard the configured query is
    checked to be a single read-only SELECT at construction; an obviously
    non-SELECT query fails fast rather than ever being executed.
    """

    name = "postgres"

    def __init__(self, dsn: str, query: str, log: logging.Logger):
        if not _is_select_only(query):
            raise ValueError(
                "sources.postgres.query must be a single read-only SELECT "
                "(optionally a WITH...SELECT CTE); statement stacking and "
                "non-SELECT statements are refused. NOTE: this is a safeguard, "
                "not the boundary -- still use a SELECT-only DB role."
            )
        self.dsn = dsn
        self.query = query
        self.log = log
        self._pool: "asyncpg.Pool | None" = None

    async def connect(self) -> None:
        if asyncpg is None:
            raise RuntimeError("asyncpg not installed; cannot use the postgres source")
        self._pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=2)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def fetch(self) -> list[str]:
        if self._pool is None:
            # transient reconnect attempt; let the caller log/skip on failure
            await self.connect()
        if self._pool is None:  # connect() failed to populate it
            raise RuntimeError("postgres pool unavailable")
        rows = await self._pool.fetch(self.query)
        # Edge validation (defense in depth): the central _clean gate in bot.py
        # is the authority, but drop anything here that isn't a valid Matrix
        # server name so a stray non-name row (NULL, a numeric id, a label) is
        # filtered at the source and counted, not silently shipped to the queue.
        out: list[str] = []
        dropped = 0
        for r in rows:
            val = r[0]
            if not val:
                continue
            name = str(val).strip()
            if validate_server_name(name):
                out.append(name)
            else:
                dropped += 1
        if dropped:
            self.log.debug("postgres source: skipped %d non-server-name row(s)", dropped)
        return out