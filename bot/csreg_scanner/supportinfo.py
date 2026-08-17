"""/.well-known/matrix/support fetcher.

Fetches ``/.well-known/matrix/support`` from the target's ORIGIN hostname over
plain HTTPS (port 443, normal TLS verification -- unlike the federation version
probe there is no custom-port / SNI-override machinery here; a well-known lives
on the origin by definition) and hands the raw JSON document to the caller for
storage.

Authoritative-answer contract (drives overwrite-vs-preserve at the write site):
a fetch is AUTHORITATIVE if it got HTTP 200 AND the size-capped body parsed as
a JSON OBJECT. The document's *schema* is deliberately NOT validated (contacts /
support_page etc.) -- we store what the server publishes; consumers interpret.
Anything else -- non-200 (including a clean 404), network error, timeout,
oversize body, non-JSON body (e.g. an HTML error page served with 200), or JSON
that is not an object -- is NON-authoritative: the caller must PRESERVE any
previously stored document. A 404 therefore never wipes stored data.

The stored value is a compact re-serialization (sorted keys) of the parsed
object, so what lands in the DB is guaranteed-valid canonical JSON and is
bounded by the same size cap that guarded the wire read.

All HTTP reads are size-capped via resolver.read_json_capped (64 KiB); the
fetcher never raises.

Redirects ARE followed: support documents commonly live behind hosting-level
redirects (apex -> www, path rewrites), and unlike the client well-known the
spec does not forbid following them here -- same posture as the server
well-known fetch in resolver.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional

import aiohttp

from .resolver import build_timeout, parse_name, read_json_capped

# Per-request read timeout. The connect phase is bounded tightly inside
# build_timeout. The CALLER additionally wraps the fetch in a wait_for bounded
# by whatever remains of the total scan budget, so this only caps one request.
_SUPPORT_READ_TIMEOUT = 8.0


@dataclass(frozen=True)
class SupportInfo:
    """Outcome of a support well-known fetch.

    ``authoritative`` is the load-bearing flag: True iff the fetch got a 200
    whose body parsed as a JSON object. Only an authoritative result is written
    to storage; a non-authoritative result tells the caller to leave any
    previously stored document untouched.

    ``raw_json`` is the compact canonical re-serialization of the parsed
    object; it is non-None exactly when ``authoritative`` is True.
    """

    authoritative: bool
    raw_json: Optional[str] = None

    @classmethod
    def no_signal(cls) -> "SupportInfo":
        """A non-authoritative result: the caller preserves prior stored data."""
        return cls(False, None)


class SupportInfoProbe:
    """Fetches a server's /.well-known/matrix/support document.

    A shared ``aiohttp.ClientSession`` is injected (connection pooling across
    scans); this probe does not own its lifecycle. Normal TLS verification
    applies -- this is a plain origin HTTPS fetch, not a federation request, so
    the shared verifying session is the right transport (no private session and
    nothing extra to close).
    """

    def __init__(self, client: aiohttp.ClientSession, log: logging.Logger) -> None:
        self.client = client
        self.log = log

    async def fetch(self, scan_target: str) -> SupportInfo:
        """Fetch the support document for ``scan_target``'s origin hostname.

        The port on the scan target is IGNORED here (a well-known is defined on
        the origin, https://<host>/), so ``matrix.org`` and ``matrix.org:8448``
        fetch the same URL -- which is why storage is keyed on the portless
        domain, not the full scan target. Never raises; any failure yields a
        non-authoritative result.
        """
        try:
            parsed = parse_name(scan_target)
        except ValueError:
            return SupportInfo.no_signal()

        # host_with_brackets re-brackets IPv6 literals so the URL stays valid;
        # for DNS names it is just the hostname.
        url = f"https://{parsed.host_with_brackets}/.well-known/matrix/support"
        try:
            async with self.client.get(
                url,
                timeout=build_timeout(_SUPPORT_READ_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    return SupportInfo.no_signal()
                data = await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug("support fetch(%s) http error: %s", scan_target, e)
            return SupportInfo.no_signal()

        # read_json_capped returns None on oversize or non-JSON. Require a JSON
        # object on top of that: a bare string/number/array is "valid JSON" but
        # not a plausible support document, and storing it would let a 200-with-
        # junk overwrite a previously good record.
        if not isinstance(data, dict):
            return SupportInfo.no_signal()

        return SupportInfo(
            True, json.dumps(data, separators=(",", ":"), sort_keys=True)
        )
