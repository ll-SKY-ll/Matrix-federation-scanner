"""Connection-target IP filtering for SCAN traffic.

A scanned server controls both halves of its own delegation -- ``m.server`` in
the server well-known and ``m.homeserver.base_url`` in the client well-known --
so it chooses the host:port the scanner connects to. Without a filter that is a
blind SSRF primitive pointed at whatever the scanner's egress can reach.

Scope: SCANS ONLY. Ingress sources are deliberately NOT filtered -- a textfile /
postgres source URL is operator-controlled by definition, and the calculator's
/counts pass-through is loopback BY DESIGN and would break under the default
blacklist.

Split-horizon DNS is why BOTH lists are configurable: an operator whose own
homeserver resolves to private space internally adds that prefix to
``ip_range_whitelist`` rather than gutting the blacklist. The default blacklist
is Synapse's, verbatim, so an operator can copy their homeserver config across;
the key names match Synapse's for the same reason.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections.abc import Sequence
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class BlockedAddressError(OSError):
    """Raised from the resolver when every resolved address for a host is denied.

    Subclasses OSError DELIBERATELY. aiohttp's TCPConnector catches OSError
    around host resolution and re-raises it as ClientConnectorError, which IS an
    aiohttp.ClientError -- so a blocked target collapses to the existing
    no-signal path at every call site (``except (aiohttp.ClientError,
    asyncio.TimeoutError)``) with no new exception handling anywhere, and the
    scan records ``unknown`` exactly as an unreachable host does. Raising a
    non-OSError here would escape those handlers and surface as a task error.
    """


class IPRangeConfigError(ValueError):
    """A restriction-bearing IP range config was malformed.

    Raised by parse_networks in strict mode (the BLACKLIST). A malformed
    blacklist signals INTENT TO RESTRICT that could not be honored, and silently
    dropping it would remove a restriction the operator explicitly asked for --
    the same reasoning that makes a malformed min_bot_version halt rather than be
    ignored. Raising here aborts start() before the scan loops are launched, so
    NO scanning happens until the config is fixed (fail closed, loudly).

    The WHITELIST is deliberately NOT strict: a whitelist only carves exceptions
    OUT of the blacklist, so dropping a bad whitelist entry fails toward MORE
    filtering (the safe direction), not less.
    """


def parse_networks(
    entries: Any, log: logging.Logger, *, field: str, strict: bool = False
) -> list[_Network]:
    """Parse a config list of CIDR strings into networks.

    ``strict=False`` (the WHITELIST): per-entry tolerance -- a typo'd prefix is
    warned about and skipped rather than taking down the plugin. Dropping a bad
    whitelist entry fails toward more restriction, which is safe.

    ``strict=True`` (the BLACKLIST): ANY problem raises IPRangeConfigError -- a
    non-list structure, a non-string/empty entry, or an invalid CIDR. A malformed
    blacklist is intent-to-restrict that can't be honored; failing closed (and
    aborting startup before scanning begins) is the only safe response. One
    typo grounds the scanner until fixed -- deliberately, because an unenforced
    blacklist entry is a silent hole in the SSRF filter.

    ``strict=False`` (ip_network) accepts a host address written with a prefix
    length (10.0.0.5/8) instead of rejecting it, the forgiving reading of intent.
    """
    nets: list[_Network] = []
    if not isinstance(entries, (list, tuple)):
        if strict and entries:
            raise IPRangeConfigError(
                f"scanner.{field} must be a list of CIDR strings, got "
                f"{type(entries).__name__}"
            )
        if entries:
            log.warning(
                "scanner.%s is not a list; ignoring", field,
                extra={"csreg_alarm": "ip_range_config_type", "field": field},
            )
        return nets
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            if strict:
                raise IPRangeConfigError(
                    f"scanner.{field}: invalid entry {entry!r} "
                    f"(expected a non-empty CIDR string)"
                )
            continue
        try:
            nets.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError as e:
            if strict:
                raise IPRangeConfigError(
                    f"scanner.{field}: invalid CIDR {entry!r} ({e})"
                ) from e
            log.warning(
                "scanner.%s: ignoring invalid CIDR %r (%s)", field, entry, e,
                extra={"csreg_alarm": "ip_range_config_invalid",
                       "field": field, "value": entry},
            )
    return nets


def _parse_address(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Best-effort parse of an address as getaddrinfo hands it back.

    Strips brackets and a scope/zone id ("fe80::1%eth0"), which ipaddress
    accepts on IPv6 but which would otherwise have to be special-cased at every
    comparison. Returns None for anything unparseable (e.g. a unix socket path),
    which the caller treats as "not an IP, nothing to decide".
    """
    a = addr.strip()
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    if "%" in a:
        a = a.split("%", 1)[0]
    try:
        return ipaddress.ip_address(a)
    except ValueError:
        return None


class IPRangePolicy:
    """Allow/deny decision over resolved connection targets.

    Whitelist is consulted FIRST and wins outright, so a split-horizon operator
    can carve their own internal prefix back out of the default blacklist
    without having to restate the rest of it. An empty blacklist means the
    policy is inert (``active`` False) and the caller installs no resolver
    wrapper at all, so the zero-config path costs nothing.
    """

    def __init__(
        self,
        blacklist: Sequence[_Network] = (),
        whitelist: Sequence[_Network] = (),
    ) -> None:
        self._deny = list(blacklist)
        self._allow = list(whitelist)

    @property
    def active(self) -> bool:
        return bool(self._deny)

    def allows(self, addr: str) -> bool:
        ip = _parse_address(addr)
        if ip is None:
            return True
        if any(ip in net for net in self._allow):
            return True
        return not any(ip in net for net in self._deny)

    def describe(self) -> str:
        return f"{len(self._deny)} denied range(s), {len(self._allow)} allowed range(s)"


class FilteringResolver(AbstractResolver):
    """aiohttp resolver wrapper that drops denied addresses.

    Filters the address LIST rather than failing on the first denied entry: a
    dual-stack host with a denied AAAA and an allowed A is still reachable over
    the allowed one, which is the same fall-through the connect path already
    relies on for a dead AAAA. Only when NOTHING survives does it raise.
    """

    def __init__(
        self,
        policy: IPRangePolicy,
        log: logging.Logger,
        inner: AbstractResolver | None = None,
    ) -> None:
        self._policy = policy
        self._log = log
        self._inner = inner if inner is not None else aiohttp.ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        infos = await self._inner.resolve(host, port, family)
        allowed = [info for info in infos if self._policy.allows(info["host"])]
        if not allowed:
            blocked = sorted({str(info["host"]) for info in infos})
            # WARNING, not debug: a blocked target is indistinguishable from an
            # unreachable one in the recorded status, so the only place an
            # operator can see that a filter (and not the network) produced the
            # `unknown` is here.
            self._log.warning(
                "blocked connection to %s: every resolved address is in a "
                "denied range (%s)", host, ", ".join(blocked),
                extra={"csreg_alarm": "ip_blocked", "host": host,
                       "addresses": blocked},
            )
            raise BlockedAddressError(
                f"all resolved addresses for {host} are in a denied IP range"
            )
        return allowed

    async def close(self) -> None:
        await self._inner.close()


class FilteringTCPConnector(aiohttp.TCPConnector):
    """TCPConnector that filters at ``_resolve_host``, closing aiohttp's
    IP-literal fast path.

    The resolver wrapper alone is NOT sufficient, and this is the whole reason
    this class exists: TCPConnector._resolve_host short-circuits when the host is
    already an IP address --

        if is_ip_address(host):
            return [{"host": host, ...}]        # resolver never consulted

    -- so a delegation pointing straight at a literal ("m.server":
    "127.0.0.1:9337", or the bracketed v6 form) skipped the filter completely.
    That is the single most likely shape of the attack, since it needs no DNS
    control at all.

    Overriding _resolve_host catches both paths (literal and resolved) in one
    place, so it is the real gate; FilteringResolver stays as defence in depth
    for anything that reaches the resolver directly.

    _resolve_host is not public API, hence the startup check in build_connector:
    if a future aiohttp removes or renames it, the override would silently stop
    filtering, which is exactly the failure mode this must not have.
    """

    def __init__(self, *args: Any, ip_policy: IPRangePolicy,
                 ip_log: logging.Logger, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._ip_policy = ip_policy
        self._ip_log = ip_log

    async def _resolve_host(
        self, host: str, port: int, *args: Any, **kwargs: Any
    ) -> list[ResolveResult]:
        infos = await super()._resolve_host(host, port, *args, **kwargs)
        allowed = [info for info in infos if self._ip_policy.allows(info["host"])]
        if not allowed:
            blocked = sorted({str(info["host"]) for info in infos})
            self._ip_log.warning(
                "blocked connection to %s: every resolved address is in a "
                "denied range (%s)", host, ", ".join(blocked),
                extra={"csreg_alarm": "ip_blocked", "host": host,
                       "addresses": blocked},
            )
            raise BlockedAddressError(
                f"all resolved addresses for {host} are in a denied IP range"
            )
        return allowed


def build_connector(
    policy: IPRangePolicy | None,
    log: logging.Logger,
    **kwargs: Any,
) -> aiohttp.TCPConnector:
    """A connector that enforces `policy`, or a plain one when it is inert.

    One place, so the three scan sessions (shared verifying client, the version
    probe's verify-off client, and the CLI/standalone client) cannot drift apart
    on which of them filters.
    """
    if policy is None or not policy.active:
        return aiohttp.TCPConnector(**kwargs)
    if not hasattr(aiohttp.TCPConnector, "_resolve_host"):
        # Fail LOUD rather than silently degrading to resolver-only filtering,
        # which would leave the IP-literal path open.
        log.error(
            "aiohttp.TCPConnector._resolve_host is missing; IP-literal "
            "delegation targets CANNOT be filtered on this aiohttp version",
            extra={"csreg_alarm": "ip_filter_hook_missing",
                   "aiohttp_version": aiohttp.__version__},
        )
        kwargs["resolver"] = FilteringResolver(policy, log)
        return aiohttp.TCPConnector(**kwargs)
    kwargs["resolver"] = FilteringResolver(policy, log)
    return FilteringTCPConnector(ip_policy=policy, ip_log=log, **kwargs)
