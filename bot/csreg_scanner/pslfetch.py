"""Online refresh of the public suffix list.

Exists so the vendored copy no longer has to be CURRENT -- only not older than
min_psl_version. That decouples suffix-list freshness from the release cadence,
which was the whole point: republishing a package to pick up a new PRIVATE
section entry is a poor use of a release.

What this module does NOT decide: whether the resulting list is acceptable.
Fetching is freshness; the floor is governance. A fetch failure therefore keeps
whatever list is already active and is NOT itself a halt -- the halt comes from
policy re-evaluating min_psl_version against whatever is active, which may well
be a cached or vendored copy. Keeping those separate is what stops a
publicsuffix.org outage from turning into a fleet-wide stop.

Politeness matters here in a way it does not for scan traffic: this hits one
volunteer-run host, from every bot in the fleet, forever. Hence conditional
requests (steady state is a 304, not 325 KiB), a daily cadence rather than a
tight loop, jitter so a fleet restarted together does not arrive in lockstep, and
a hard refusal to accept a mirror URL.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass

import aiohttp

from .psl import (
    _MAX_FETCH_BYTES,
    PSL_URL,
    PSLValidationError,
    PublicSuffixList,
    validate_psl_text,
)

# Read timeout for one fetch. Generous: this is a 325 KiB body from a single
# host and it is never on a scan's critical path.
_FETCH_TIMEOUT = 30.0

# Jitter as a fraction of the interval, applied +/- so a fleet spreads out.
_JITTER_FRACTION = 0.15


@dataclass(frozen=True)
class FetchOutcome:
    """Result of one refresh attempt.

    `not_modified` is a SUCCESS, distinct from `psl is None` meaning failure: a
    304 proves the cached copy is current, which is exactly what we wanted to
    learn, and must not be logged as an error or it will be the loudest line in
    the log for the 364 days a year the list has not changed since our last poll.
    """

    psl: PublicSuffixList | None = None
    not_modified: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.psl is not None or self.not_modified


class PSLFetcher:
    """Fetches and validates the list over HTTPS.

    Uses the caller's VERIFYING session. This is emphatically not the federation
    version probe's verify-off client: that one exists to look at hostile servers
    and disables certificate checks to do it, whereas this fetch feeds the data
    that decides ban bucketing, so an unauthenticated or tampered response is a
    correctness problem. Redirects are followed (publicsuffix.org has historically
    redirected) but the scheme is pinned to https.
    """

    def __init__(self, http: aiohttp.ClientSession, log: logging.Logger) -> None:
        self._http = http
        self.log = log
        # Validators from the last successful 200, replayed as conditional
        # request headers. Held in memory only: losing them across a restart
        # costs one extra full body, which is cheaper than persisting them and
        # having them disagree with the cached blob.
        self._etag: str | None = None
        self._last_modified: str | None = None

    async def fetch(self) -> FetchOutcome:
        requested_https = PSL_URL.startswith("https://")
        headers = {"Accept": "text/plain"}
        if self._etag:
            headers["If-None-Match"] = self._etag
        if self._last_modified:
            headers["If-Modified-Since"] = self._last_modified
        try:
            async with self._http.get(
                PSL_URL,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=_FETCH_TIMEOUT),
                allow_redirects=True,
            ) as resp:
                if resp.status == 304:
                    return FetchOutcome(not_modified=True)
                if resp.status != 200:
                    return FetchOutcome(error=f"HTTP {resp.status}")
                if requested_https and resp.url.scheme != "https":
                    # Redirect chain downgraded the scheme. Refuse rather than
                    # accept ban-bucketing data over plaintext. Phrased as
                    # DOWNGRADE protection (compared against what we asked for)
                    # rather than "must be https", so it states the actual threat
                    # and stays exercisable against a plain-HTTP test server.
                    return FetchOutcome(
                        error=f"redirect downgraded https -> {resp.url.scheme}"
                    )
                body = await self._read_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return FetchOutcome(error=f"{type(e).__name__}: {e}")
        except PSLValidationError as e:
            return FetchOutcome(error=f"oversize: {e}")

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as e:
            return FetchOutcome(error=f"not utf-8: {e}")
        try:
            psl = validate_psl_text(text, source="fetched")
        except PSLValidationError as e:
            # Validation failure is louder than a network failure: the host
            # answered 200 with something that is not a suffix list, which is
            # either an outage serving an error page or something worse.
            return FetchOutcome(error=f"validation failed: {e}")

        self._etag = resp.headers.get("ETag") or None
        self._last_modified = resp.headers.get("Last-Modified") or None
        return FetchOutcome(psl=psl)

    @staticmethod
    async def _read_capped(resp: aiohttp.ClientResponse) -> bytes:
        """Stream with a hard byte cap.

        Capped during streaming rather than via Content-Length, which a server is
        free to omit or lie about. The real list is ~325 KiB against a 4 MiB cap,
        so this only ever fires on something pathological.
        """
        buf = bytearray()
        async for chunk in resp.content.iter_chunked(64 * 1024):
            buf.extend(chunk)
            if len(buf) > _MAX_FETCH_BYTES:
                raise PSLValidationError(
                    f"body exceeded {_MAX_FETCH_BYTES} bytes"
                )
        return bytes(buf)


def jittered_interval(interval: float) -> float:
    """`interval` +/- _JITTER_FRACTION, floored at a minute.

    Without jitter, a fleet brought up by the same orchestration lands on
    publicsuffix.org simultaneously, every day, forever.
    """
    spread = interval * _JITTER_FRACTION
    return max(60.0, interval + random.uniform(-spread, spread))
