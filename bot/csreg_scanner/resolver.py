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

Dependencies: httpx, dnspython.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx
import dns.asyncresolver
from dns.exception import DNSException

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


def build_timeout(read_timeout: float) -> httpx.Timeout:
    """An httpx.Timeout with a tight connect phase and a caller-set read phase.

    Splitting these is what bounds the dead-AAAA-then-fall-back-to-A case: the
    connect attempt to a dead address fails in ~_CONNECT_TIMEOUT rather than
    consuming the whole per-request window.
    """
    return httpx.Timeout(read_timeout, connect=_CONNECT_TIMEOUT)


async def read_json_capped(response: httpx.Response) -> Optional[Any]:
    """Read a streaming response body up to _MAX_BODY_BYTES and JSON-parse it.

    Returns the parsed object, or None if the body overflows the cap or is not
    valid JSON. The caller MUST have opened ``response`` via ``client.stream``.
    Never raises on overflow/parse; the connection is torn down by the
    ``stream`` context manager on return.
    """
    buf = bytearray()
    async for chunk in response.aiter_bytes(_CHUNK):
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
    tls_server_name: Optional[str]
    resolution_method: ResolutionMethod

    def to_dict(self) -> dict:
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

    base_url: Optional[str]

    def to_dict(self) -> dict:
        return {"base_url": self.base_url}


@dataclass
class ServerResolution:
    server_name: str
    federation: FederationTarget
    client: ClientTarget = field(default_factory=lambda: ClientTarget(None))

    def to_dict(self) -> dict:
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
    port: Optional[int]      # explicit port, or None
    is_ip_literal: bool
    host_with_brackets: str  # host as written, IPv6 re-bracketed (for headers)


def parse_name(name: str) -> ParsedName:
    """Parse ``<host>[:<port>]`` per the Matrix grammar.

    IPv6 literals must be bracketed: ``[2001:db8::1]`` or ``[2001:db8::1]:8448``.
    Raises ValueError on a malformed bracketed literal or non-numeric port.
    """
    name = name.strip()

    if name.startswith("["):
        close = name.index("]")  # ValueError if no closing bracket
        host = name[1:close]
        rest = name[close + 1:]
        port = int(rest[1:]) if rest.startswith(":") else None
        ipaddress.IPv6Address(host)  # ValueError if malformed
        return ParsedName(host, port, True, f"[{host}]")

    if name.count(":") == 1:
        host, _, port_s = name.rpartition(":")
        port: Optional[int] = int(port_s)
    else:
        host, port = name, None

    return ParsedName(host, port, _is_ip_literal(host), host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host_header(host: str, port: Optional[int]) -> str:
    return f"{host}:{port}" if port is not None else host


# --------------------------------------------------------------------------- #
# Federation resolver (server-server)
# --------------------------------------------------------------------------- #

class ServerResolver:
    """Resolves a Matrix server name to a federation :class:`FederationTarget`.

    :param client: shared ``httpx.AsyncClient`` used for well-known fetches.
    :param dns_resolver: optional ``dns.asyncresolver.Resolver``; the default
        system resolver is used when not given.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        dns_resolver: Optional[dns.asyncresolver.Resolver] = None,
    ) -> None:
        self.client = client
        self.dns = dns_resolver or dns.asyncresolver.Resolver()

    async def resolve(self, server_name: str) -> FederationTarget:
        parsed = parse_name(server_name)

        # Step 1: IP literal -> use directly (cert validated against the IP).
        if parsed.is_ip_literal:
            return FederationTarget(
                host=parsed.host,
                port=parsed.port or DEFAULT_FEDERATION_PORT,
                host_header=_host_header(parsed.host_with_brackets, parsed.port),
                tls_server_name=None,
                resolution_method=ResolutionMethod.IP_LITERAL,
            )

        # Step 2: hostname with explicit port -> use directly, no well-known/SRV.
        if parsed.port is not None:
            return FederationTarget(
                host=parsed.host,
                port=parsed.port,
                host_header=_host_header(parsed.host, parsed.port),
                tls_server_name=parsed.host,
                resolution_method=ResolutionMethod.EXPLICIT_PORT,
            )

        # Step 3: no port -> well-known delegation, attempted BEFORE SRV and
        # short-circuiting it.
        m_server = await self._fetch_well_known_server(parsed.host)
        if m_server is not None:
            delegated = await self._resolve_delegated(m_server)
            if delegated is not None:
                return delegated
            # A malformed m.server value falls through to SRV on the original
            # name, matching the "well-known error -> step 4" behaviour.

        # Step 4: SRV on the original hostname.
        srv = await self._srv_lookup(parsed.host)
        if srv is not None:
            target, port = srv
            return FederationTarget(
                host=target,
                port=port,
                host_header=parsed.host,            # original name, no port
                tls_server_name=parsed.host,
                resolution_method=ResolutionMethod.SRV,
            )

        # Step 5: plain hostname on the default port.
        return FederationTarget(
            host=parsed.host,
            port=DEFAULT_FEDERATION_PORT,
            host_header=parsed.host,
            tls_server_name=parsed.host,
            resolution_method=ResolutionMethod.PLAIN,
        )

    async def _resolve_delegated(self, m_server: str) -> Optional[FederationTarget]:
        """Resolve the ``m.server`` delegated name (step 3 sub-branches).

        Host header / SNI are derived from the *delegated* name. Returns None if
        the value is unparseable (caller then falls through to SRV).
        """
        try:
            d = parse_name(m_server)
        except ValueError:
            return None

        # 3a: delegated name is an IP literal.
        if d.is_ip_literal:
            return FederationTarget(
                host=d.host,
                port=d.port or DEFAULT_FEDERATION_PORT,
                host_header=_host_header(d.host_with_brackets, d.port),
                tls_server_name=None,
                resolution_method=ResolutionMethod.WELL_KNOWN_IP,
            )

        # 3b: delegated name has an explicit port.
        if d.port is not None:
            return FederationTarget(
                host=d.host,
                port=d.port,
                host_header=_host_header(d.host, d.port),
                tls_server_name=d.host,
                resolution_method=ResolutionMethod.WELL_KNOWN_PORT,
            )

        # 3c: delegated name, no port -> SRV on the delegated name.
        srv = await self._srv_lookup(d.host)
        if srv is not None:
            target, port = srv
            return FederationTarget(
                host=target,
                port=port,
                host_header=d.host,                 # delegated name, no port
                tls_server_name=d.host,
                resolution_method=ResolutionMethod.WELL_KNOWN_SRV,
            )

        # 3d: delegated name, no port, no SRV -> plain on the default port.
        return FederationTarget(
            host=d.host,
            port=DEFAULT_FEDERATION_PORT,
            host_header=d.host,
            tls_server_name=d.host,
            resolution_method=ResolutionMethod.WELL_KNOWN_PLAIN,
        )

    async def _fetch_well_known_server(self, hostname: str) -> Optional[str]:
        """Fetch /.well-known/matrix/server, return ``m.server`` or None.

        Any failure (non-200, network error, oversize body, bad JSON,
        missing/!str key) yields None, which the caller treats as "no
        delegation" and falls to SRV. Redirects are allowed (the server-server
        spec permits them here). Body is size-capped.
        """
        url = f"https://{hostname}/.well-known/matrix/server"
        try:
            async with self.client.stream(
                "GET", url,
                timeout=build_timeout(_WELL_KNOWN_READ_TIMEOUT),
                follow_redirects=True,
            ) as resp:
                if resp.status_code != 200:
                    return None
                data = await read_json_capped(resp)
        except httpx.HTTPError:
            return None
        if not isinstance(data, dict):
            return None
        m_server = data.get("m.server")
        if not isinstance(m_server, str) or not m_server.strip():
            return None
        return m_server.strip()

    async def _srv_lookup(self, hostname: str) -> Optional[tuple[str, int]]:
        """SRV lookup: modern ``_matrix-fed._tcp`` then deprecated ``_matrix._tcp``."""
        for service in (f"_matrix-fed._tcp.{hostname}", f"_matrix._tcp.{hostname}"):
            target = await self._query_srv(service)
            if target is not None:
                return target
        return None

    async def _query_srv(self, qname: str) -> Optional[tuple[str, int]]:
        try:
            answers = await self.dns.resolve(qname, "SRV")
        except (
            dns.asyncresolver.NXDOMAIN,
            dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers,
        ):
            return None
        except DNSException:
            return None

        records = list(answers)
        if not records:
            return None

        # Lowest priority wins; among equal priority, choose by weight (RFC 2782).
        best_priority = min(r.priority for r in records)
        candidates = [r for r in records if r.priority == best_priority]
        chosen = _weighted_choice(candidates)

        target = str(chosen.target).rstrip(".")
        if not target or target == ".":  # explicit "no service offered"
            return None
        return target, chosen.port


def _weighted_choice(records: list):
    total = sum(r.weight for r in records)
    if total == 0:
        return random.choice(records)
    pick = random.uniform(0, total)
    upto = 0
    for r in records:
        upto += r.weight
        if pick <= upto:
            return r
    return records[-1]


# --------------------------------------------------------------------------- #
# Client resolver (client-server)
# --------------------------------------------------------------------------- #

class ClientResolver:
    """Resolves a Matrix server name to a client-API base URL via
    .well-known/matrix/client.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

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
            async with self.client.stream(
                "GET", url,
                timeout=build_timeout(_WELL_KNOWN_READ_TIMEOUT),
                follow_redirects=False,
            ) as resp:
                if resp.status_code != 200:
                    return ClientTarget(None)
                data = await read_json_capped(resp)
        except httpx.HTTPError:
            return ClientTarget(None)

        if not isinstance(data, dict):
            return ClientTarget(None)
        homeserver = data.get("m.homeserver")
        if not isinstance(homeserver, dict):
            return ClientTarget(None)
        base_url = homeserver.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            return ClientTarget(None)

        # Validate it parses as an http(s) URL; strip any trailing slash.
        try:
            parsed_url = httpx.URL(base_url)
        except httpx.InvalidURL:
            return ClientTarget(None)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.host:
            return ClientTarget(None)
        return ClientTarget(base_url=str(parsed_url).rstrip("/"))


# --------------------------------------------------------------------------- #
# Convenience: resolve both halves at once
# --------------------------------------------------------------------------- #

async def resolve_all(
    server_name: str,
    client: httpx.AsyncClient,
    dns_resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> ServerResolution:
    fed = await ServerResolver(client, dns_resolver).resolve(server_name)
    cli = await ClientResolver(client).resolve(server_name)
    return ServerResolution(server_name=server_name, federation=fed, client=cli)