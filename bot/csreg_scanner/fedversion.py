"""Federation server-version probe.

Fetches ``/_matrix/federation/v1/version`` from a server's resolved FEDERATION
endpoint (NOT the client-server endpoint) and extracts the advertised
``server.name`` / ``server.version`` strings for the version-distribution metric.

TLS posture: verification is DELIBERATELY relaxed (no cert chain/hostname/expiry
checks) for this probe only. The version string is non-security-relevant
reconnaissance feeding a metric -- a MITM's worst outcome is a wrong dashboard
row, never a trust/policy decision. Doing federation-grade cert validation
correctly would require per-branch SNI override (the cert name is the delegated
/ original name, not the connect host, on every SRV-terminating branch), which
is disproportionate machinery for a stats string. So we accept an unauthenticated
read here.

Authoritative-answer contract (drives overwrite-vs-preserve in db.record_scan):
an answer is AUTHORITATIVE iff the probe got HTTP 200, the body parsed as a JSON
object, AND that object carried a ``server`` object containing BOTH the ``name``
and ``version`` keys (their values MAY be null/empty -- the keys must be present).
Anything else -- non-200, unparseable, oversize, missing either key, federation
resolution failure, network error, timeout -- is NON-authoritative and the caller
preserves any previously stored values. An authoritative answer overwrites the
stored values with exactly what was reported (including overwriting a prior
non-null to null).

All HTTP reads are size-capped via resolver.read_json_capped; the probe never
raises.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

import aiohttp

from .resolver import (
    ServerResolver,
    build_timeout,
    read_json_capped,
)

# Per-request read timeout for the version probe. The connect phase is bounded
# tightly inside build_timeout. The CALLER additionally wraps the whole
# resolve+probe in a wait_for bounded by whatever remains of the total scan
# budget, so this only caps a single request.
_VERSION_READ_TIMEOUT = 8.0

# Field length cap. The name/version strings become Prometheus label values; an
# arbitrary server-controlled string could otherwise bloat the exposition text
# or label storage. 60 CHARACTERS (codepoint-safe slice, not bytes) is generous
# for any real implementation name or version while shutting down abuse. This is
# a sanity guard, not a cardinality control (we intentionally do not collapse
# version strings -- fresh releases must stay visible).
_FIELD_CHAR_CAP = 60


def _truncate_field(value: Any) -> Optional[str]:
    """Normalize one reported field into a stored value.

    Returns None when the value is not a non-empty string (caller treats the
    pair's nulls as "reported null", distinct from "probe failed"). Otherwise
    strips surrounding whitespace FIRST, then truncates to _FIELD_CHAR_CAP
    characters (truncation is the last transform, per design). A value that is
    only whitespace collapses to None.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:_FIELD_CHAR_CAP]


@dataclass(frozen=True)
class FederationVersion:
    """Outcome of a federation version probe.

    ``authoritative`` is the load-bearing flag: True iff the probe got a 200 with
    a parseable body carrying BOTH server.name and server.version keys. Only an
    authoritative result overwrites stored values; a non-authoritative result
    tells the caller to PRESERVE whatever was stored before.

    ``name`` / ``version`` are the normalized (stripped + 60-char-capped) reported
    strings, or None when the field was absent/null/empty/non-string. They are
    only meaningful when ``authoritative`` is True; a non-authoritative result
    always carries (None, None) and they must not be stored.
    """

    authoritative: bool
    name: Optional[str] = None
    version: Optional[str] = None

    @classmethod
    def no_signal(cls) -> "FederationVersion":
        """A non-authoritative result: the caller preserves prior stored values."""
        return cls(False, None, None)


class FederationVersionProbe:
    """Resolves a server's federation endpoint and reads its version document.

    A shared ``aiohttp.ClientSession`` is injected for connection pooling, but
    note the version probe issues its requests with TLS verification relaxed
    (see module docstring); it does this via a dedicated verify-disabled session
    rather than mutating the shared client.
    """

    def __init__(self, client: aiohttp.ClientSession, log: logging.Logger) -> None:
        self.log = log
        # The injected client carries the connection pool / headers we want, but
        # we must issue the actual GET with verification disabled. aiohttp fixes
        # the TLS posture on the connector at construction, so we keep a
        # dedicated session whose connector has ssl=False for the probe. It does
        # not own the injected client's lifecycle. The session owns this private
        # connector (connector_owner defaults True), so close() tears it down.
        self._resolver = ServerResolver(client)
        self._verify_off = aiohttp.ClientSession(
            headers={
                "User-Agent": "csreg-scanner/1.0 (registration scanner; +https://github.com/ll-SKY-ll/Matrix-federation-scanner)",
                "Accept": "application/json",
            },
            connector=aiohttp.TCPConnector(ssl=False),  # relaxed: recon only
            trust_env=False,
        )

    async def aclose(self) -> None:
        """Close the dedicated verify-off client owned by this probe."""
        await self._verify_off.close()

    async def probe(self, scan_target: str) -> FederationVersion:
        """Resolve the federation endpoint for ``scan_target`` and read its
        version document. Never raises; any failure yields a non-authoritative
        result (caller preserves prior values).

        The full scan_target (including any port) is fed to the federation
        resolver as-is -- the port is load-bearing.
        """
        try:
            target = await self._resolver.resolve(scan_target)
        except Exception as e:  # noqa: BLE001 -- resolver shouldn't raise, but never let it
            self.log.debug("fedversion resolve(%s) failed: %s", scan_target, e)
            return FederationVersion.no_signal()

        # Build the connect URL from the resolved federation target. host may be
        # a bare IPv6 literal (resolver strips brackets); re-bracket for the URL.
        host = target.host
        if ":" in host and not host.startswith("["):
            url_host = f"[{host}]"
        else:
            url_host = host
        url = f"https://{url_host}:{target.port}/_matrix/federation/v1/version"

        # Honor the federation Host header (delegated/original name, per branch).
        headers = {"Host": target.host_header}

        try:
            async with self._verify_off.get(
                url,
                headers=headers,
                timeout=build_timeout(_VERSION_READ_TIMEOUT),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    return FederationVersion.no_signal()
                body = await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug("fedversion probe(%s) http error: %s", scan_target, e)
            return FederationVersion.no_signal()

        return self._interpret(body)

    @staticmethod
    def _interpret(body: object) -> FederationVersion:
        """Apply the authoritative-answer contract to a parsed body.

        Authoritative iff body is a dict carrying a ``server`` dict that has BOTH
        ``name`` and ``version`` keys present (values may be null). The reported
        values are normalized (strip + cap); a present-but-null/empty/non-string
        value normalizes to None and STILL counts as authoritative (the server
        truthfully reported a null), overwriting any prior stored value.
        """
        if not isinstance(body, dict):
            return FederationVersion.no_signal()
        server = body.get("server")
        if not isinstance(server, dict):
            return FederationVersion.no_signal()
        # Both keys must be PRESENT (membership), regardless of value.
        if "name" not in server or "version" not in server:
            return FederationVersion.no_signal()
        name = _truncate_field(server.get("name"))
        version = _truncate_field(server.get("version"))
        return FederationVersion(True, name, version)