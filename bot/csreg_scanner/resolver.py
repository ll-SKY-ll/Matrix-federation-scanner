"""Matrix server discovery / resolution (async).

Implementation of the Matrix server-name resolution
algorithms, written from the published specification:

  * server-server "Resolving server names"
    https://spec.matrix.org/latest/server-server-api/#resolving-server-names
  * client-server ".well-known" discovery
    https://spec.matrix.org/latest/client-server-api/#well-known-uri

The federation algorithm is *strictly ordered*: well-known delegation is
attempted before SRV and short-circuits it. Branches are never raced.

All HTTP reads are size-capped (see ``read_json_capped``): a hostile or broken
server cannot stream unbounded data at the resolver. Failures, oversize bodies
and malformed documents collapse to "no delegation"; the resolver never raises
on network/parse errors.

Dependencies: aiohttp, dnspython.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

import aiohttp
import dns.asyncresolver
import yarl
from dns.exception import DNSException
from dns.rdtypes.IN.SRV import SRV

DEFAULT_FEDERATION_PORT = 8448

# --- safety rails (hardcoded; not operator-tunable) -------------------------- #
# A well-known / metadata document is a few hundred bytes to a few KB in
# practice. 64 KiB is generous headroom while still shutting down a server that
# tries to stream garbage at us. Read in 8 KiB chunks so we bail within one
# chunk of crossing the cap. The connect timeout is kept tight so a dead address
# (e.g. a stale AAAA on an otherwise v4-reachable host) fails fast and the OS
# can fall through to the next address well inside the per-request budget.
_MAX_BODY_BYTES = 64 * 1024
_CHUNK = 8 * 1024
_CONNECT_TIMEOUT = 3.0
_WELL_KNOWN_READ_TIMEOUT = 10.0


def build_timeout(read_timeout: float) -> aiohttp.ClientTimeout:
    """An aiohttp.ClientTimeout with a tight connect phase and a caller-set read
    phase.

    Splitting these is what bounds the dead-AAAA-then-fall-back-to-A case: the
    connect attempt to a dead address fails in ~_CONNECT_TIMEOUT rather than
    consuming the whole per-request window. ``sock_connect`` bounds the TCP
    connect to a single address and ``sock_read`` bounds inactivity between
    reads; ``total`` is deliberately left unset so a legitimately slow-but-
    progressing body isn't cut off mid-stream (the size cap, not a wall-clock,
    is what stops a hostile slow-drip -- and the caller wraps the whole scan in
    its own total-budget wait_for).
    """
    return aiohttp.ClientTimeout(sock_connect=_CONNECT_TIMEOUT, sock_read=read_timeout)


async def read_json_capped(response: aiohttp.ClientResponse) -> Any | None:
    """Read a streaming response body up to _MAX_BODY_BYTES and JSON-parse it.

    Returns the parsed object, or None if the body overflows the cap or is not
    valid JSON. The caller MUST be inside the ``async with session.get(...)``
    context for ``response`` (the body is streamed off the live connection).
    Never raises on overflow/parse; the connection is released by the
    ``session.get`` context manager on return.
    """
    buf = bytearray()
    async for chunk in response.content.iter_chunked(_CHUNK):
        buf.extend(chunk)
        if len(buf) > _MAX_BODY_BYTES:
            return None  # oversize -> treat as no usable response
    try:
        import json
        return json.loads(buf)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #

class ResolutionMethod(str, Enum):
    """Which branch of the federation algorithm produced the result."""

    IP_LITERAL = "ip_literal"              # step 1
    EXPLICIT_PORT = "explicit_port"        # step 2
    WELL_KNOWN_IP = "well_known_ip"        # step 3, m.server is an IP literal
    WELL_KNOWN_PORT = "well_known_port"    # step 3, m.server has explicit port
    WELL_KNOWN_SRV = "well_known_srv"      # step 3, m.server resolved via SRV
    WELL_KNOWN_PLAIN = "well_known_plain"  # step 3, m.server plain :8448
    SRV = "srv"                            # step 4
    PLAIN = "plain"                        # step 5


@dataclass
class FederationTarget:
    """Everything needed to open a federation request to the server.

    ``host`` is the host to open the TCP connection against (a hostname or an IP
    literal); the connecting client performs final A/AAAA resolution.
    ``host_header`` is the literal value for the HTTP ``Host`` header.
    ``tls_server_name`` is the SNI / certificate name to validate against, or
    None for IP literals (where the certificate is validated against the IP).
    """

    host: str
    port: int
    host_header: str
    tls_server_name: str | None
    resolution_method: ResolutionMethod

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "host_header": self.host_header,
            "tls_server_name": self.tls_server_name,
            "resolution_method": self.resolution_method.value,
        }


@dataclass
class ClientTarget:
    """Client-server base URL from .well-known/matrix/client.

    ``base_url`` is None when the server publishes no usable client well-known;
    the caller decides whether to fall back to ``https://<server_name>``.
    """

    base_url: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"base_url": self.base_url}


@dataclass
class ServerResolution:
    server_name: str
    federation: FederationTarget
    client: ClientTarget = field(default_factory=lambda: ClientTarget(None))

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "federation": self.federation.to_dict(),
            "client": self.client.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Parsing  <host>[:<port>]
# --------------------------------------------------------------------------- #

@dataclass
class ParsedName:
    host: str                # hostname or IP literal (IPv6 WITHOUT brackets)
    port: int | None      # explicit port, or None
    is_ip_literal: bool
    host_with_brackets: str  # host as written, IPv6 re-bracketed (for headers)


def parse_name(name: str) -> ParsedName:
    """Parse ``<host>[:<port>]`` per the Matrix grammar.

    IPv6 literals must be bracketed: ``[2001:db8::1]`` or ``[2001:db8::1]:8448``.
    Raises ValueError on a malformed bracketed literal or non-numeric port.
    """
    name = name.strip()
    port: int | None = None

    if name.startswith("["):
        close = name.index("]")  # ValueError if no closing bracket
        host = name[1:close]
        rest = name[close + 1:]
        port = int(rest[1:]) if rest.startswith(":") else None
        ipaddress.IPv6Address(host)  # ValueError if malformed
        return ParsedName(host, port, True, f"[{host}]")

    if name.count(":") == 1:
        host, _, port_s = name.rpartition(":")
        port = int(port_s)
    else:
        host, port = name, None

    return ParsedName(host, port, _is_ip_literal(host), host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_header(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port is not None else host


# --------------------------------------------------------------------------- #
# Federation resolver (server-server)
# --------------------------------------------------------------------------- #

class ServerResolver:
    """Resolves a Matrix server name to a federation :class:`FederationTarget`.

    :param client: shared ``aiohttp.ClientSession`` used for well-known fetches.
    :param dns_resolver: optional ``dns.asyncresolver.Resolver``; the default
        system resolver is used when not given.
    """

    def __init__(
        self,
        client: aiohttp.ClientSession,
        dns_resolver: dns.asyncresolver.Resolver | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self.client = client
        self.dns = dns_resolver or dns.asyncresolver.Resolver()
        # Injected by the bot so resolver debug lines ride the instance logger
        # (its level + the scan-target filter). Falls back to a module logger for
        # standalone/CLI use, where it still surfaces under --debug.
        self.log = log or logging.getLogger(__name__)

    async def resolve(self, server_name: str) -> FederationTarget:
        """The single preferred federation target (first candidate).

        Kept for callers that only want one -- the CLI's resolution display.
        Anything that CONNECTS should use resolve_candidates() so a dead
        primary SRV target can fall through to its backups.
        """
        return (await self.resolve_candidates(server_name))[0]

    async def resolve_candidates(self, server_name: str) -> list[FederationTarget]:
        """Every federation target to try, in the order to try them.

        Only the SRV branches (steps 3c and 4) can yield more than one: RFC 2782
        defines a priority/weight ORDER over the record set, and a client is
        expected to walk it until one target connects. The previous code picked a
        single record and never fell back, so a server whose primary SRV target
        was down classified as `unknown` forever even with a healthy backup
        record -- and, if it was banned, stale cleanup would eventually drop its
        rule on the strength of that `unknown`.

        The non-SRV branches are single-candidate BY SPEC, not by simplification:
        an IP literal, an explicit port, or a bare name on :8448 name exactly one
        endpoint, and there is nothing to fall back to. In particular a plain
        :8448 is NOT appended after an SRV list -- if SRV records exist, they are
        the answer.
        """
        parsed = parse_name(server_name)

        # Step 1: IP literal -> use directly (cert validated against the IP).
        if parsed.is_ip_literal:
            return [FederationTarget(
                host=parsed.host,
                port=parsed.port or DEFAULT_FEDERATION_PORT,
                host_header=_host_header(parsed.host_with_brackets, parsed.port),
                tls_server_name=None,
                resolution_method=ResolutionMethod.IP_LITERAL,
            )]

        # Step 2: hostname with explicit port -> use directly, no well-known/SRV.
        if parsed.port is not None:
            return [FederationTarget(
                host=parsed.host,
                port=parsed.port,
                host_header=_host_header(parsed.host, parsed.port),
                tls_server_name=parsed.host,
                resolution_method=ResolutionMethod.EXPLICIT_PORT,
            )]

        # Step 3: no port -> well-known delegation, attempted BEFORE SRV and
        # short-circuiting it.
        m_server = await self._fetch_well_known_server(parsed.host)
        if m_server is not None:
            delegated = await self._resolve_delegated(m_server)
            if delegated:
                self.log.debug(
                    "resolve(%s): well-known delegates to m.server=%s "
                    "(%d federation target(s))",
                    server_name, m_server, len(delegated),
                )
                return delegated
            # A malformed m.server value falls through to SRV on the original
            # name, matching the "well-known error -> step 4" behaviour.
            self.log.debug(
                "resolve(%s): m.server=%s is unparseable; falling through to "
                "SRV on the original name", server_name, m_server,
            )

        # Step 4: SRV on the original hostname.
        srv = await self._srv_lookup(parsed.host)
        if srv:
            self.log.debug(
                "resolve(%s): SRV on original name -> %d target(s), first "
                "%s:%d", server_name, len(srv), srv[0][0], srv[0][1],
            )
            return [
                FederationTarget(
                    host=target,
                    port=port,
                    host_header=parsed.host,        # original name, no port
                    tls_server_name=parsed.host,
                    resolution_method=ResolutionMethod.SRV,
                )
                for target, port in srv
            ]

        # Step 5: plain hostname on the default port.
        self.log.debug(
            "resolve(%s): no delegation or SRV; plain %s:%d",
            server_name, parsed.host, DEFAULT_FEDERATION_PORT,
        )
        return [FederationTarget(
            host=parsed.host,
            port=DEFAULT_FEDERATION_PORT,
            host_header=parsed.host,
            tls_server_name=parsed.host,
            resolution_method=ResolutionMethod.PLAIN,
        )]

    async def _resolve_delegated(self, m_server: str) -> list[FederationTarget]:
        """Resolve the ``m.server`` delegated name (step 3 sub-branches).

        Host header / SNI are derived from the *delegated* name. Returns an EMPTY
        list if the value is unparseable (caller then falls through to SRV on the
        original name).
        """
        try:
            d = parse_name(m_server)
        except ValueError:
            return []

        # 3a: delegated name is an IP literal.
        if d.is_ip_literal:
            return [FederationTarget(
                host=d.host,
                port=d.port or DEFAULT_FEDERATION_PORT,
                host_header=_host_header(d.host_with_brackets, d.port),
                tls_server_name=None,
                resolution_method=ResolutionMethod.WELL_KNOWN_IP,
            )]

        # 3b: delegated name has an explicit port.
        if d.port is not None:
            return [FederationTarget(
                host=d.host,
                port=d.port,
                host_header=_host_header(d.host, d.port),
                tls_server_name=d.host,
                resolution_method=ResolutionMethod.WELL_KNOWN_PORT,
            )]

        # 3c: delegated name, no port -> SRV on the delegated name.
        srv = await self._srv_lookup(d.host)
        if srv:
            return [
                FederationTarget(
                    host=target,
                    port=port,
                    host_header=d.host,             # delegated name, no port
                    tls_server_name=d.host,
                    resolution_method=ResolutionMethod.WELL_KNOWN_SRV,
                )
                for target, port in srv
            ]

        # 3d: delegated name, no port, no SRV -> plain on the default port.
        return [FederationTarget(
            host=d.host,
            port=DEFAULT_FEDERATION_PORT,
            host_header=d.host,
            tls_server_name=d.host,
            resolution_method=ResolutionMethod.WELL_KNOWN_PLAIN,
        )]

    async def _fetch_well_known_server(self, hostname: str) -> str | None:
        """Fetch /.well-known/matrix/server, return ``m.server`` or None.

        Any failure (non-200, network error, oversize body, bad JSON,
        missing/!str key) yields None, which the caller treats as "no
        delegation" and falls to SRV. Redirects are allowed (the server-server
        spec permits them here). Body is size-capped.
        """
        url = f"https://{hostname}/.well-known/matrix/server"
        try:
            async with self.client.get(
                url,
                timeout=build_timeout(_WELL_KNOWN_READ_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    self.log.debug(
                        "well-known server(%s): HTTP %d -> no delegation",
                        hostname, resp.status,
                    )
                    return None
                data = await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug(
                "well-known server(%s): fetch failed (%s) -> no delegation",
                hostname, e,
            )
            return None
        if not isinstance(data, dict):
            return None
        m_server = data.get("m.server")
        if not isinstance(m_server, str) or not m_server.strip():
            self.log.debug(
                "well-known server(%s): 200 but no usable m.server -> no "
                "delegation", hostname,
            )
            return None
        return m_server.strip()

    async def _srv_lookup(self, hostname: str) -> list[tuple[str, int]]:
        """SRV lookup: modern ``_matrix-fed._tcp`` then deprecated ``_matrix._tcp``.

        Returns ALL usable records in RFC 2782 try-order, not just the winner.
        The first service name that yields a usable answer wins outright -- an
        answer on ``_matrix-fed._tcp`` is never merged with, or supplemented by,
        the deprecated name.
        """
        for service in (f"_matrix-fed._tcp.{hostname}", f"_matrix._tcp.{hostname}"):
            targets = await self._query_srv(service)
            if targets:
                return targets
        return []

    async def _query_srv(self, qname: str) -> list[tuple[str, int]]:
        try:
            answers = await self.dns.resolve(qname, "SRV")
        except DNSException:
            # NXDOMAIN / NoAnswer / NoNameservers (the normal "no SRV record"
            # outcomes) and any other DNS-layer failure all subclass
            # DNSException and mean the same thing here: no usable SRV answer ->
            # fall through to the next resolution step. DNSException is the
            # stable public base (dns.exception), so this avoids coupling to
            # version-specific re-exports on dns.asyncresolver.
            return []

        records = cast(list[SRV], list(answers))
        if not records:
            return []

        out: list[tuple[str, int]] = []
        for record in _order_srv(records):
            target = str(record.target).rstrip(".")
            if not target or target == ".":
                # RFC 2782's explicit "no service offered" pseudo-target. Drop it
                # rather than aborting: if it was the ONLY record the list comes
                # back empty and the caller falls through, which is the same
                # behaviour as before.
                continue
            out.append((target, record.port))
        return out


def _order_srv(records: list[SRV]) -> list[SRV]:
    """Order an SRV record set per RFC 2782: ascending priority, and within each
    priority band, repeated weighted selection WITHOUT replacement.

    Selection without replacement is what makes this an order rather than a
    single pick: every record in a band appears exactly once, and a record's
    weight determines how likely it is to appear EARLY, not whether it appears
    at all. That is the property the fallback walk needs -- a weight-0 backup
    must still be reachable once the weighted primaries have been tried.
    """
    by_priority: dict[int, list[SRV]] = {}
    for record in records:
        by_priority.setdefault(record.priority, []).append(record)
    ordered: list[SRV] = []
    for priority in sorted(by_priority):
        band = list(by_priority[priority])
        while band:
            # pop by INDEX, not by value: SRV rdata compares by field, so two
            # identical records would make a remove()-by-value ambiguous.
            ordered.append(band.pop(_weighted_pick_index(band)))
    return ordered


def _weighted_pick_index(records: list[SRV]) -> int:
    """RFC 2782 weighted pick within one priority band; returns an index.

    ``pick < upto`` is strict on purpose. random.uniform(0, total) is INCLUSIVE
    of 0, so under the old ``pick <= upto`` a zero-weight record sitting on a
    cumulative boundary (in particular a weight-0 record in first position, with
    upto still 0) could win a lottery it holds no tickets in -- a zero-length
    segment being hit because the comparison treated its closed left edge as
    inside it. Strict comparison makes a zero-weight record unreachable while any
    positive weight remains, and the trailing return covers pick == total.
    """
    total = sum(r.weight for r in records)
    if total == 0:
        # All-zero band: the RFC leaves this undefined, so treat them as equals.
        return random.randrange(len(records))
    pick = random.uniform(0, total)
    upto = 0
    for i, record in enumerate(records):
        upto += record.weight
        if pick < upto:
            return i
    return len(records) - 1


# --------------------------------------------------------------------------- #
# Client resolver (client-server)
# --------------------------------------------------------------------------- #

class ClientResolver:
    """Resolves a Matrix server name to a client-API base URL via
    .well-known/matrix/client.
    """

    def __init__(
        self, client: aiohttp.ClientSession, log: logging.Logger | None = None
    ) -> None:
        self.client = client
        self.log = log or logging.getLogger(__name__)

    async def resolve(self, server_name: str) -> ClientTarget:
        """Return the client base URL, or ClientTarget(None) if none is published.

        Per the client-server discovery rules, a 404 / non-200 / oversize /
        malformed document yields no delegation; the caller may default to
        ``https://<hostname>``. Redirects are NOT followed (client discovery
        forbids them). Body is size-capped.
        """
        try:
            parsed = parse_name(server_name)
        except ValueError:
            return ClientTarget(None)

        url = f"https://{parsed.host}/.well-known/matrix/client"
        try:
            async with self.client.get(
                url,
                timeout=build_timeout(_WELL_KNOWN_READ_TIMEOUT),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    self.log.debug(
                        "client well-known(%s): HTTP %d -> no delegation",
                        server_name, resp.status,
                    )
                    return ClientTarget(None)
                data = await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug(
                "client well-known(%s): fetch failed (%s) -> no delegation",
                server_name, e,
            )
            return ClientTarget(None)

        if not isinstance(data, dict):
            return ClientTarget(None)
        homeserver = data.get("m.homeserver")
        if not isinstance(homeserver, dict):
            return ClientTarget(None)
        base_url = homeserver.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            return ClientTarget(None)

        # Validate it parses as an http(s) URL; strip any trailing slash. yarl
        # is lenient (it does not raise on a junk string -- it just yields an
        # empty scheme/host), so the scheme/host check below is the real gate;
        # the broad except is a belt-and-braces guard so any parse surprise
        # still collapses to "no delegation" rather than raising.
        try:
            parsed_url = yarl.URL(base_url)
        except Exception:  # noqa: BLE001 -- any parse failure -> no delegation
            return ClientTarget(None)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.host:
            return ClientTarget(None)
        return ClientTarget(base_url=str(parsed_url).rstrip("/"))


# --------------------------------------------------------------------------- #
# Convenience: resolve both halves at once
# --------------------------------------------------------------------------- #

async def resolve_all(
    server_name: str,
    client: aiohttp.ClientSession,
    dns_resolver: dns.asyncresolver.Resolver | None = None,
) -> ServerResolution:
    fed = await ServerResolver(client, dns_resolver).resolve(server_name)
    cli = await ClientResolver(client).resolve(server_name)
    return ServerResolution(server_name=server_name, federation=fed, client=cli)
