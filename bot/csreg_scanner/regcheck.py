"""Matrix server registration status classifier.

Determines a homeserver's registration posture by probing its client-server
API and interpreting the responses. 

Status vocabulary (a subset of taxonomy.KNOWN_STATUSES is emitted):

  dangerously_open  registration completable with NO verifying stage
  open              registration possible, every flow gated by a verifier
  oauth             auth is delegated to an OAuth/OIDC provider
  closed            registration affirmatively disabled
  unknown           anything indeterminate: failure, ambiguity, or surprise

Classification is start-from-unknown and promote-only-on-certainty: a target is
labelled with a definite status ONLY when a well-formed response unambiguously
warrants it. Every failure, timeout, oversize body, malformed document, or
unhandled exception collapses to ``unknown``. The classifier never raises.

Precedence (most dangerous applicable label wins):

    dangerously_open  >  oauth  >  open  >  closed  >  unknown

dangerously_open outranks oauth deliberately: a server may *advertise* OAuth
delegation while *still* serving a live, unguarded legacy registration flow
(migration window, misconfiguration, or deception). A working zero-friction
path is the most dangerous fact about the server, so it wins regardless of what
the server announces.

All HTTP reads are size-capped via resolver.read_json_capped, so a hostile
server cannot stream unbounded data at the scanner.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import aiohttp
import yarl

from .fedversion import FederationVersion, FederationVersionProbe
from .ipfilter import IPRangePolicy, build_connector
from .resolver import (
    ClientResolver,
    build_timeout,
    parse_name,
    read_json_capped,
)
from .supportinfo import SupportInfo, SupportInfoProbe

# --- status constants (must exist in taxonomy.KNOWN_STATUSES) ---------------- #

DANGEROUSLY_OPEN = "dangerously_open"
OPEN = "open"
OAUTH = "oauth"
CLOSED = "closed"
UNKNOWN = "unknown"

# Per-request read timeout for the probes (the connect phase is bounded tightly
# inside build_timeout). The Scanner wraps the whole classification in a single
# total-budget wait_for, so this only caps an individual request.
_PROBE_READ_TIMEOUT = 8.0


# --- the verifier allowlist -------------------------------------------------- #
# A flow is "guarded" if it contains at least one of these stages. The set is
# an ALLOWLIST of things that count as friction.
# Though given this auth is now legacy there likely won't be any new stuff added to this.
VERIFYING_STAGES: frozenset[str] = frozenset(
    {
        "m.login.email.identity",
        "m.login.msisdn",
        "m.login.recaptcha",
        "m.login.registration_token",
        # Some deployments still advertise the pre-stabilisation spelling.
        "org.matrix.msc3231.login.registration_token",
    }
)

# Stages that are known to impose NO friction (a bot can satisfy them
# unattended). A flow built ENTIRELY from these (or an empty stage list) is
# genuinely zero-friction and is the only thing that earns dangerously_open.
_NON_VERIFYING: frozenset[str] = frozenset({"m.login.dummy", "m.login.terms"})


@dataclass(frozen=True)
class ScanResult:
    """Preserved verbatim from the previous subprocess scanner so the bot's
    call sites (db.record_scan, policy.reconcile) need no change.

    ``ok`` is True when classification produced a status we trust (including a
    deliberate ``unknown``); ``ok`` is False only when the scan itself failed in
    a retry-worthy way and ``error`` explains why. ``status`` carries the label.
    """

    ok: bool
    status: str | None
    error: str | None = None


def _flow_classification(stages: object) -> str | None:
    """Classify a single flow's ``stages`` list into a precedence label.

    Returns:
      DANGEROUSLY_OPEN -- no verifier present AND every stage is a known
                          non-verifier (dummy/terms) or the list is empty: a
                          genuinely zero-friction path a bot can walk unattended.
      OPEN             -- no verifier present BUT at least one stage is
                          unrecognised: completable in principle, but the
                          unfamiliar stage might impose friction, so we do NOT
                          escalate to dangerous.
      None             -- the flow contains a verifying stage (guarded), or the
                          flow is malformed: no evidence of an unguarded path.

    Note the deliberate inversion of the old bias: an all-unrecognised flow now
    biases toward OPEN rather than DANGEROUSLY_OPEN. Only flows we can affirm are
    frictionless (empty, or exclusively dummy/terms) reach dangerously_open.
    """
    if not isinstance(stages, list):
        return None  # malformed flow: not evidence of an unguarded path
    str_stages = [s for s in stages if isinstance(s, str)]
    if any(s in VERIFYING_STAGES for s in str_stages):
        return None  # guarded
    if all(s in _NON_VERIFYING for s in str_stages):
        return DANGEROUSLY_OPEN  # empty list or only dummy/terms
    return OPEN  # at least one unrecognised stage -> treat as open, not dangerous


def classify_register_body(body: object) -> str | None:
    """Interpret a 401 UIA registration body. Returns dangerously_open / open,
    or None if the body has no usable flows (caller treats None as no-signal).

    A single genuinely frictionless flow makes the whole server
    dangerously_open (an attacker just picks that path). Failing that, any flow
    that is completable-but-unrecognised yields open. An all-guarded body falls
    through to open as well, matching the prior contract.
    """
    if not isinstance(body, dict):
        return None
    flows = body.get("flows")
    if not isinstance(flows, list) or not flows:
        return None

    saw_valid_flow = False
    result: str | None = None
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        stages = flow.get("stages")
        if not isinstance(stages, list):
            continue
        saw_valid_flow = True
        verdict = _flow_classification(stages)
        if verdict == DANGEROUSLY_OPEN:
            # Highest precedence: an attacker simply picks this frictionless
            # path, so other gated/unrecognised flows are irrelevant.
            return DANGEROUSLY_OPEN
        if verdict == OPEN:
            result = OPEN  # remember, but keep scanning for a dangerous flow

    if not saw_valid_flow:
        return None
    return result or OPEN


class RegistrationChecker:
    """Classifies one server's registration posture over the client-server API.

    A shared ``aiohttp.ClientSession`` is injected (connection pooling across
    scans). The checker resolves the client base URL, then probes the legacy
    registration endpoint and the OAuth-delegation discovery endpoints, and
    applies the precedence ladder.
    """

    def __init__(self, client: aiohttp.ClientSession, log: logging.Logger) -> None:
        self.client = client
        self.log = log
        self._client_resolver = ClientResolver(client, log)

    async def classify(self, scan_target: str) -> str:
        """Return one of the status constants. Never raises; indeterminate
        cases return UNKNOWN.

        The full scan_target (including any port) is used as-is for resolution
        and probing -- the port is load-bearing and must not be stripped here.
        """
        try:
            base_url, well_known = await self._base_url(scan_target)
            if base_url is None:
                self.log.debug(
                    "classify(%s): server name did not resolve to a base URL "
                    "-> unknown", scan_target,
                )
                return UNKNOWN
            self.log.debug(
                "classify(%s): base_url=%s client_well_known=%s",
                scan_target, base_url,
                "present" if well_known is not None else "absent",
            )

            # Gather both signals before deciding -- do NOT short-circuit on
            # oauth, because a live unguarded legacy flow must be able to
            # override an oauth announcement.
            legacy = await self._probe_register(base_url, scan_target=scan_target)
            if legacy == DANGEROUSLY_OPEN:
                self.log.debug(
                    "classify(%s): unguarded legacy registration flow "
                    "-> dangerously_open", scan_target,
                )
                return DANGEROUSLY_OPEN  # highest precedence, wins outright

            if await self._is_oauth_delegated(
                base_url, well_known, scan_target=scan_target
            ):
                self.log.debug(
                    "classify(%s): OAuth/OIDC delegation detected -> oauth",
                    scan_target,
                )
                return OAUTH

            if legacy in (OPEN, CLOSED):
                self.log.debug(
                    "classify(%s): legacy register signal -> %s",
                    scan_target, legacy,
                )
                return legacy

            self.log.debug(
                "classify(%s): no trustworthy signal from any probe -> unknown",
                scan_target,
            )
            return UNKNOWN
        except Exception as e:  # noqa: BLE001 -- never let a scan raise
            self.log.debug("classify(%s) unexpected error: %s", scan_target, e)
            return UNKNOWN

    # --- resolution ----------------------------------------------------------

    async def _base_url(self, scan_target: str) -> tuple[str | None, dict[str, Any] | None]:
        """Resolve the client base URL and return the raw client well-known doc
        alongside it (reused by oauth detection to avoid a second fetch).

        Defaults to ``https://<host>`` when no client well-known is published
        (the spec's IGNORE outcome). Returns (None, _) only when the target name
        itself is unparseable.
        """
        well_known = await self._fetch_client_well_known(scan_target)

        base_url: str | None = None
        if isinstance(well_known, dict):
            hs = well_known.get("m.homeserver")
            if isinstance(hs, dict) and isinstance(hs.get("base_url"), str) and hs["base_url"]:
                # yarl is lenient (no raise on junk -> empty scheme/host), so
                # the scheme/host check is the gate; the broad except is a guard
                # so any parse surprise leaves base_url None (fall back below).
                try:
                    u = yarl.URL(hs["base_url"])
                    if u.scheme in ("http", "https") and u.host:
                        base_url = str(u).rstrip("/")
                except Exception:  # noqa: BLE001 -- bad URL -> fall back to https://<host>
                    base_url = None

        if base_url is None:
            try:
                parsed = parse_name(scan_target)
            except ValueError:
                return None, well_known if isinstance(well_known, dict) else None
            base_url = f"https://{parsed.host_with_brackets}"

        return base_url, well_known if isinstance(well_known, dict) else None

    async def _fetch_client_well_known(self, scan_target: str) -> Any | None:
        """Fetch and size-cap /.well-known/matrix/client. None on any failure."""
        try:
            parsed = parse_name(scan_target)
        except ValueError:
            self.log.debug(
                "client well-known(%s): unparseable server name", scan_target
            )
            return None
        url = f"https://{parsed.host}/.well-known/matrix/client"
        try:
            async with self.client.get(
                url,
                timeout=build_timeout(_PROBE_READ_TIMEOUT),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    self.log.debug(
                        "client well-known(%s): HTTP %d -> no client well-known;"
                        " using https://<host> as base URL",
                        scan_target, resp.status,
                    )
                    return None
                return await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug(
                "client well-known(%s): fetch failed (%s) -> no client "
                "well-known; using https://<host> as base URL", scan_target, e,
            )
            return None

    # --- probes --------------------------------------------------------------

    async def _probe_register(
        self, base_url: str, *, scan_target: str = "-"
    ) -> str | None:
        """Probe POST /_matrix/client/v3/register with an empty body.

        Returns dangerously_open / open / closed when the response is a
        well-formed, understood answer; None when there is no usable signal
        (endpoint absent/unrecognised, oversize, or unparseable body). None is
        NOT closed -- only an affirmative "registration disabled" is closed.

        A 403 is treated as closed ONLY when the body affirmatively carries
        errcode "M_FORBIDDEN" (the spec signal for disabled registration). 
        A 403 from any other cause -- a WAF / CDN bot-challenge, 
        a per-IP/geo allowlist that blocks our datacenter egress while the 
        server registers fine for real users, or a flow-level rejection of 
        the empty body -- carries a different errcode or no JSON at all, 
        and collapses to no-signal (-> unknown), NOT closed. Recording unknown 
        for an ambiguous 403 keeps a still-dangerous server from being 
        mislabelled closed and unbanned.
        """
        url = f"{base_url}/_matrix/client/v3/register"
        try:
            async with self.client.post(
                url,
                json={},
                timeout=build_timeout(_PROBE_READ_TIMEOUT),
                allow_redirects=False,
            ) as resp:
                status = resp.status
                if status not in (400, 401, 403):
                    # 404 / 5xx / 429 / 200-with-junk / anything else -> no
                    # trustworthy signal.
                    self.log.debug(
                        "register probe(%s): HTTP %d -> no legacy signal",
                        scan_target, status,
                    )
                    return None
                # Read the body for all three handled codes. A 403's errcode is
                # what distinguishes a real "registration disabled" from an
                # unrelated forbidden (WAF / IP allowlist / flow rejection).
                body = await read_json_capped(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.log.debug(
                "register probe(%s): request failed: %s", scan_target, e
            )
            return None

        if status == 401:
            # UIA challenge: the body advertises the available flows.
            verdict = classify_register_body(body)
            self.log.debug(
                "register probe(%s): 401 UIA -> %s", scan_target,
                verdict if verdict is not None else "no usable flows (no signal)",
            )
            return verdict

        if status == 403:
            # Affirmative refusal ONLY if the body says M_FORBIDDEN. Anything
            # else (other errcode, non-dict body, unparseable/oversize -> None)
            # is not a trustworthy "disabled" signal and must not become closed.
            if isinstance(body, dict) and body.get("errcode") == "M_FORBIDDEN":
                self.log.debug(
                    "register probe(%s): 403 M_FORBIDDEN -> closed", scan_target
                )
                return CLOSED
            errcode = body.get("errcode") if isinstance(body, dict) else None
            self.log.debug(
                "register probe(%s): 403 errcode=%s -> no signal (not treated "
                "as closed)", scan_target, errcode,
            )
            return None

        # status == 400: M_UNRECOGNIZED means the endpoint isn't served (common
        # on OAuth-delegated servers) -> no legacy signal, not closed. Any other
        # 400 is likewise not a trustworthy registration signal.
        errcode = body.get("errcode") if isinstance(body, dict) else None
        self.log.debug(
            "register probe(%s): 400 errcode=%s -> no legacy signal",
            scan_target, errcode,
        )
        return None

    async def _is_oauth_delegated(
        self,
        base_url: str,
        well_known: dict[str, Any] | None,
        *,
        scan_target: str = "-",
    ) -> bool:
        """Detect OAuth/OIDC delegation (MSC2965).

        Two signals, either suffices: the spec'd auth-metadata endpoint
        returning an issuer, or the client well-known carrying an
        ``m.authentication`` (a.k.a. ``org.matrix.msc2965.authentication``)
        block with an issuer. Detection only -- signup policy is not assessed.
        The well-known doc fetched during base-URL resolution is reused here.
        """
        # 1) client well-known authentication block (already in hand).
        if isinstance(well_known, dict):
            for key in ("m.authentication", "org.matrix.msc2965.authentication"):
                block = well_known.get(key)
                if isinstance(block, dict) and isinstance(block.get("issuer"), str) and block["issuer"]:
                    self.log.debug(
                        "oauth probe(%s): issuer in client well-known %s",
                        scan_target, key,
                    )
                    return True

        # 2) auth_metadata endpoint (v1, then the unstable fallback MAS serves).
        for path in (
            "/_matrix/client/v1/auth_metadata",
            "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
        ):
            try:
                async with self.client.get(
                    f"{base_url}{path}",
                    timeout=build_timeout(_PROBE_READ_TIMEOUT),
                    allow_redirects=False,
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await read_json_capped(resp)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
            if isinstance(data, dict) and isinstance(data.get("issuer"), str) and data["issuer"]:
                self.log.debug(
                    "oauth probe(%s): issuer at %s", scan_target, path
                )
                return True

        return False


# --------------------------------------------------------------------------- #
# Scanner -- drop-in replacement for the former subprocess wrapper.
# --------------------------------------------------------------------------- #

class Scanner:
    """In-process registration scanner.

    Preserves the prior interface shape: ``async scan(scan_target)`` -- but now
    returns ``(ScanResult, FederationVersion, SupportInfo)``: registration
    classification PLUS a federation /version probe result PLUS the support
    well-known document. ``timeout`` is the TOTAL budget for the whole scan of
    one target; classification runs first under that budget, then the version
    probe and support fetch consume whatever wall-clock REMAINS of it, in that
    order (see ``scan``).
    The bot owns concurrency (it fans out scans and bounds them by batch size),
    so this handles a single target per call.
    """

    def __init__(
        self,
        timeout: float,
        log: logging.Logger,
        client: aiohttp.ClientSession | None = None,
        pool_limit: int | None = None,
        fetch_support: bool = True,
        ip_policy: IPRangePolicy | None = None,
    ) -> None:
        self.timeout = timeout
        self.log = log
        # A shared client should be injected by the bot and closed by it. When
        # none is given (standalone/CLI use) we own a private one -- and then the
        # address filter has to be installed here, since there is no bot-built
        # connector to inherit it from.
        self._owns_client = client is None
        self.client = client or self._build_client(ip_policy, log)
        self._checker = RegistrationChecker(self.client, log)
        # Federation version probe. It keeps its OWN verify-disabled aiohttp
        # session internally (regcheck's client verifies TLS; the version probe
        # must not), so it is always closed by aclose() regardless of who owns
        # self.client. pool_limit (the bot's scan-admission ceiling) is threaded
        # through so the probe's private connection pool is sized to the same
        # ceiling and can never become a second, silent concurrency limiter.
        self._version = FederationVersionProbe(
            self.client, log, pool_limit=pool_limit, ip_policy=ip_policy
        )
        # Support well-known fetcher (config-gated via fetch_support). Plain
        # origin HTTPS on the SHARED verifying session -- it borrows the same
        # pool an in-flight scan already holds a slot in, so it adds no second
        # limiter and there is nothing extra to close.
        self.fetch_support = fetch_support
        self._support = SupportInfoProbe(self.client, log)

    @staticmethod
    def _build_client(
        ip_policy: IPRangePolicy | None = None,
        log: logging.Logger | None = None,
    ) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            headers={
                "User-Agent": "csreg-scanner (registration scanner; +https://github.com/ll-SKY-ll/Matrix-federation-scanner)",
                "Accept": "application/json",
            },
            connector=build_connector(
                ip_policy, log or logging.getLogger(__name__)
            ),
            timeout=build_timeout(_PROBE_READ_TIMEOUT),
            trust_env=False,  # no ambient proxy/env surprises in a scanner
        )

    async def scan(
        self, scan_target: str
    ) -> tuple[ScanResult, FederationVersion, SupportInfo]:
        """Scan one target: classify registration, then probe federation version,
        then fetch the support well-known.

        Returns ``(ScanResult, FederationVersion, SupportInfo)``. ``self.timeout``
        bounds the WHOLE scan. The three phases share that one wall-clock budget
        in strict priority order:

          1. Classification runs first, under its own wait_for(self.timeout) --
             unchanged behaviour and unchanged priority. A timeout here is a
             SUCCESS with status ``unknown`` (an unreachable/slow server is a
             real, recordable observation), matching the prior contract.

          2. The version probe runs ONLY if classification succeeded as a task
             (``ok``) and wall-clock remains, and is bounded by exactly that
             remainder. The version string is a nice-to-have; reg status is the
             thing policy acts on, so the probe never delays or steals budget
             from classification.

          3. The support fetch runs last (and only when ``fetch_support`` is
             enabled), under whatever remains after the version probe -- it is
             the least important signal and the first thing sacrificed when a
             slow target eats the budget. Like the version probe it is skipped
             entirely when the reg-scan failed as a task.

        Non-authoritative outcomes for phases 2 and 3 (including "no time left"
        and "reg scan failed") yield no_signal(), which tells the write path to
        PRESERVE previously stored data.

        Never raises; failures of any phase are captured in the returned values.
        """
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        try:
            status = await asyncio.wait_for(
                self._checker.classify(scan_target), timeout=self.timeout
            )
            result = ScanResult(True, status)
        except asyncio.TimeoutError:
            self.log.debug("scan(%s) timed out after %.1fs", scan_target, self.timeout)
            # Classification ate the whole budget -> no time for the follow-ups.
            return ScanResult(True, UNKNOWN), FederationVersion.no_signal(), \
                SupportInfo.no_signal()
        except Exception as e:  # noqa: BLE001 -- defensive; classify shouldn't raise
            # Task-failure: skip the follow-up phases entirely (they are
            # independent signals, but a failed reg scan suppresses them).
            return ScanResult(False, None, f"unexpected: {e}"), \
                FederationVersion.no_signal(), SupportInfo.no_signal()

        # Version probe under the REMAINING budget. Skip if none is left.
        version = FederationVersion.no_signal()
        remaining = self.timeout - (loop.time() - t0)
        if remaining > 0:
            try:
                version = await asyncio.wait_for(
                    self._version.probe(scan_target), timeout=remaining
                )
            except asyncio.TimeoutError:
                self.log.debug("version probe(%s) timed out", scan_target)
            except Exception as e:  # noqa: BLE001 -- probe shouldn't raise
                self.log.debug("version probe(%s) error: %s", scan_target, e)

        # Support well-known fetch under what is STILL left, gated on config.
        support = SupportInfo.no_signal()
        if self.fetch_support:
            remaining = self.timeout - (loop.time() - t0)
            if remaining > 0:
                try:
                    support = await asyncio.wait_for(
                        self._support.fetch(scan_target), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    self.log.debug("support fetch(%s) timed out", scan_target)
                except Exception as e:  # noqa: BLE001 -- fetcher shouldn't raise
                    self.log.debug("support fetch(%s) error: %s", scan_target, e)

        return result, version, support

    async def aclose(self) -> None:
        """Close owned resources. The version probe always owns its private
        verify-disabled client, so close it unconditionally. The main client is
        closed only when WE own it (the bot closes an injected shared client)."""
        await self._version.aclose()
        if self._owns_client:
            await self.client.close()
