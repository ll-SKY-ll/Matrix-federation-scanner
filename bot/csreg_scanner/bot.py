"""net.codestorm.csreg -- decentralized open-registration scanner.

Main plugin: orchestrates ingress clocks, the queue-draining scan tick, the
most-overdue rescan tick, policy governance, and the metrics server.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import pkgutil
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp
from aiohttp.web import Request, Response
from maubot import Plugin  # type: ignore[attr-defined]
from maubot.handlers import web
from mautrix.api import Method, Path
from mautrix.client import EventHandler
from mautrix.types import EventType, RoomID, StateEvent
from mautrix.util.async_db import UpgradeTable
from mautrix.util.config import BaseProxyConfig

from .config import Config
from .db import DB, upgrade_table
from .ipfilter import IPRangePolicy, build_connector, parse_networks
from .logcontext import ScanTargetFilter, bind_scan_target
from .metrics import MetricsServer
from .policy import POLICY_RULE_SERVER, PolicyManager
from .psl import (
    PSLHolder,
    PSLValidationError,
    load_vendored_psl,
    validate_psl_text,
)
from .pslfetch import PSLFetcher, jittered_interval
from .regcheck import Scanner
from .sources import PolicyListSource, PostgresSource, Source, TextFileSource
from .taxonomy import KNOWN_STATUSES
from .util import now, strip_port, validate_server_name

# EWMA weight for the rolling average scan duration.
_EWMA_ALPHA = 0.2

# How often to retry loading governance state (the policy-rule fold and the
# auto_config event) after a failed read. The bot stays halted for the whole
# retry window, so this is a "how fast do we recover from a homeserver hiccup"
# knob, not a correctness one -- and it is deliberately not operator-tunable.
_GOVERNANCE_RETRY_SECONDS = 60

# Suffix-list refresh cadence. Daily, jittered: the list changes a few times a
# week at most, and this hits one volunteer-run host from every bot in the fleet.
_PSL_REFRESH_SECONDS = 24 * 60 * 60

# Retry cadence while the suffix list is DEGRADED -- no list at all, or an active
# list below min_psl_version. Both are states a fetch could resolve, and both
# block policy writes when a cap is configured, so waiting a full day to try
# again would leave the bot needlessly halted. Doubles up to the normal interval
# so a floor that no published list can satisfy (a typo, or a stamp from the
# future) degrades to daily polling instead of hammering publicsuffix.org from
# every bot in the fleet forever.
_PSL_DEGRADED_RETRY_SECONDS = 10 * 60

# Default staleness T (seconds) for any status with no explicit
# rescan.staleness_seconds entry, used when `unknown` (which normally supplies
# this default) is itself unconfigured. One day. Single source of truth for both
# the sanitizer's warning and _required_rate's fallback so they can't drift.
_DEFAULT_STALENESS_SECONDS = 86_400


def _sanitize_staleness(
    raw: Any, log: logging.Logger
) -> dict[str, int]:
    """Validate the rescan.staleness_seconds config into a clean {status: int}.

    Extracted from start() so it is testable in isolation (no Plugin runtime).

    Rules, each dropping the offending entry with a structured warning:
      * a key not in KNOWN_STATUSES is dropped -- both prevents bad SQL (keys are
        interpolated into a CASE by db.most_overdue) and surfaces a config typo
        that would otherwise silently fall through to the default T.
      * a non-integer value is dropped.
      * a non-positive value is dropped (a <= 0 T would be a divide-by-zero /
        meaningless deadline).

    Finally, if there is no ``unknown`` entry, warn ONCE: `unknown` doubles as the
    default T for any unmapped status (see _required_rate), so its absence
    silently makes that default the hardcoded _DEFAULT_STALENESS_SECONDS. The
    warning goes here, at config load, rather than in _required_rate, which runs
    every rescan tick and would spam the same line forever.
    """
    staleness: dict[str, int] = {}
    for status, secs in dict(raw or {}).items():
        if status not in KNOWN_STATUSES:
            log.warning(
                "rescan.staleness_seconds: ignoring unknown status %r", status,
                extra={"csreg_alarm": "staleness_unknown_status", "key": status},
            )
            continue
        try:
            seconds = int(secs)
        except (TypeError, ValueError):
            log.warning(
                "rescan.staleness_seconds[%s]: %r is not a whole number of "
                "seconds; ignoring", status, secs,
                extra={"csreg_alarm": "staleness_invalid_value",
                       "key": status, "value": secs},
            )
            continue
        if seconds <= 0:
            log.warning(
                "rescan.staleness_seconds[%s]: must be > 0, got %r; ignoring",
                status, secs,
                extra={"csreg_alarm": "staleness_invalid_value",
                       "key": status, "value": secs},
            )
            continue
        staleness[status] = seconds

    if "unknown" not in staleness:
        log.warning(
            "rescan.staleness_seconds: no 'unknown' entry; unmapped statuses "
            "will fall back to the default of %d seconds",
            _DEFAULT_STALENESS_SECONDS,
            extra={"csreg_alarm": "staleness_unknown_unset"},
        )
    return staleness

# MSC4133 custom profile field advertising this plugin's running version.
_VERSION_PROFILE_FIELD = "net.codestorm.federation-scanner.version"

# -- Calculator UI --------------------------------------------------------------
# The page itself lives in csreg_scanner/web/calc.html (shipped as an extra_file
# and loaded via pkgutil so it works from inside the .mbp zip). 
# Self-contained: inline CSS/JS, system font stack, no
# external assets (DSGVO). Duration-free model -- the calculator sizes the
# rescan loop from counts + staleness targets only; measured scan duration never
# enters the math:
#   required_rate = Sum(N_bucket / T_bucket)          servers/sec needed
#   throughput    = rescan.batch_limit / interval     servers/sec configured
#   sustainable   <=>  throughput >= required_rate * safety
# Two free variables (interval, batch_limit) solve each other live:
#   given interval    -> min batch_limit = ceil(required * safety * interval)
#   given batch_limit -> max interval    = floor(batch_limit / (required*safety))
# The new-server scan loop has no staleness target (queue is ~empty after the
# baseline import), so it is a passive readout, not something the solver tunes.
_CALC_HTML_CACHE: str | None = None


def _load_calc_html() -> str:
    """Load the calculator page from the package, caching after first read.
    Falls back to a minimal error page if the asset is missing (shouldn't
    happen in a correctly-packaged .mbp, but never 500 the route over it)."""
    global _CALC_HTML_CACHE
    if _CALC_HTML_CACHE is None:
        data = pkgutil.get_data("csreg_scanner", "web/calc.html")
        if not data:
            return ("<!DOCTYPE html><meta charset=utf-8><title>csreg</title>"
                    "<p>calculator asset missing from package "
                    "(csreg_scanner/web/calc.html)")
        _CALC_HTML_CACHE = data.decode("utf-8")
    return _CALC_HTML_CACHE


class CSRegScanner(Plugin):
    db: DB
    scanner: Scanner
    policy: PolicyManager
    metrics: MetricsServer | None = None
    _pg: PostgresSource | None = None

    @property
    def cfg(self) -> BaseProxyConfig:
        assert self.config is not None, "config accessed before load"
        return self.config

    @classmethod
    def get_config_class(cls) -> type[Config]:
        return Config

    @classmethod
    def get_db_upgrade_table(cls) -> UpgradeTable | None:
        return upgrade_table

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        assert self.config is not None, "start() requires loaded config"
        assert self.database is not None, "start() requires a database"
        self.config.load_and_update()

        # Logging verbosity config, unrelated to maubots own setting so this
        # plugin can have log levels independently of whats set in the global
        # maubot yaml.
        # A typo'd level falls back to INFO with an alarm rather than raising.
        level_name = str(self.cfg["log_level"]).upper()
        level = getattr(logging, level_name, None)
        if not isinstance(level, int):
            self.log.warning(
                "log_level %r not recognized; using INFO", self.cfg["log_level"],
                extra={"csreg_alarm": "log_level_invalid",
                       "value": self.cfg["log_level"]},
            )
            level = logging.INFO
        self.log.setLevel(level)
        # Attach the per-scan context filter once. The logger object survives a
        # config reload (it is maubot's, not ours), so guard against stacking a
        # duplicate filter on each restart.
        if not any(isinstance(f, ScanTargetFilter) for f in self.log.filters):
            self.log.addFilter(ScanTargetFilter())

        self.db = DB(self.database)

        self._tasks: list[asyncio.Task[None]] = []
        self._avg_scan: float = 5.0  # seed; refined by EWMA (metrics only)
        # In-flight scans, keyed by scan_target. One structure, three jobs:
        #   (a) strong refs so the GC can't collect a running scan mid-flight
        #       (asyncio only weak-refs tasks); exceptions still get logged via
        #       the done-callback and stop() can cancel anything running;
        #   (b) duplicate-launch guard: a target already being scanned is never
        #       launched again. Without this, most_overdue keeps re-picking a
        #       slow target every rescan tick until its terminal write lands
        #       (scan budget >> rescan interval), turning the slowest servers
        #       into N concurrent scans of themselves while burning the credit
        #       genuinely-due servers should have gotten;
        #   (c) admission control: len(self._inflight) vs _max_inflight is the
        #       ONE concurrency limiter (see _max_inflight below).
        self._inflight: dict[str, asyncio.Task[None]] = {}

        # Global in-flight ceiling. DERIVED from the two batch knobs the
        # operator already tunes -- deliberately NOT a third config option, so
        # concurrency can never be restricted in two different places.
        # Launches beyond the ceiling are DEFERRED (skipped this tick, loudly 
        # logged + metered, and retried on the next tick: queue rows stay 
        # leased/reclaimable, rescan credit is retained).
        self._max_inflight: int = max(
            1,
            int(self.cfg["queue.scan_batch_limit"])
            + int(self.cfg["rescan.batch_limit"]),
        )

        # Rescan rate-meter (leaky bucket). Each tick we add required_rate*interval
        # "credits" and launch floor(credit) most-overdue servers, so the long-run
        # scan rate matches demand (sum N_b/T_b) instead of bursting the entire
        # overdue set the instant deadlines cross. In-memory: resets to 0 on
        # restart and re-converges within a few ticks.
        self._rescan_credit: float = 0.0

        # Per-status staleness T (seconds), sanitized once at config load.
        self._staleness: dict[str, int] = _sanitize_staleness(
            self.cfg["rescan.staleness_seconds"], self.log
        )
        # scanner: in-process registration checker over a shared aiohttp client.
        # The client is pooled across all scans and closed in stop(); the
        # Scanner does not own it (aclose() is a no-op for an injected client).
        # Timeouts: 3s connect (a dead address -- e.g. a stale AAAA on an
        # otherwise v4-reachable host -- fails fast and the loop falls through
        # to the next address), 8s read per request; the TOTAL per-target budget
        # is scanner.timeout_seconds, enforced inside Scanner.scan via wait_for.
        # Connector: sized to exactly the admission ceiling. Every scan issues
        # its probes as sequential awaits, so an in-flight scan holds at most
        # ONE connection on this session at a time.
        #
        # Connection-target IP filter, applied to SCAN traffic only. A scanned
        # server picks the host:port we connect to (m.server / m.homeserver.
        # base_url), so without this it can aim the scanner at loopback or
        # RFC1918. Installed on the connector's RESOLVER, not checked against the
        # target name, because the name is usually a DNS record and a name
        # pointing at 10.0.0.1 would otherwise sail through -- that also covers
        # redirect chains for free. Ingress sources and the /calc/data
        # pass-through keep their own unfiltered sessions on purpose (source URLs
        # are operator-controlled, and /counts is loopback by design and would
        # break under the default blacklist).
        self._ip_policy = IPRangePolicy(
            parse_networks(
                self.cfg["scanner.ip_range_blacklist"], self.log,
                field="ip_range_blacklist", strict=True,
            ),
            parse_networks(
                self.cfg["scanner.ip_range_whitelist"], self.log,
                field="ip_range_whitelist",
            ),
        )
        self._http_client = aiohttp.ClientSession(
            connector=build_connector(
                self._ip_policy, self.log, limit=self._max_inflight
            ),
            headers={"User-Agent": "csreg-scanner (registration scanner; +https://github.com/ll-SKY-ll/Matrix-federation-scanner)", "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(sock_connect=3.0, sock_read=8.0),
            trust_env=False,
        )
        self.scanner = Scanner(
            float(self.cfg["scanner.timeout_seconds"]),
            self.log,
            client=self._http_client,
            pool_limit=self._max_inflight,
            fetch_support=bool(self.cfg["scanner.fetch_support"]),
            ip_policy=self._ip_policy,
        )

        # policy governance
        #
        # Suffix-list plumbing all comes before PolicyManager, which reads three
        # pieces of it: the holder (the cap-and-floor evaluation in
        # _apply_auto_config needs a list to compare against), the wake setter,
        # and the auto-update flag.
        #
        # The fetcher is constructed only when enabled, so "auto-update off"
        # means it does not EXIST rather than merely being unreachable. Costs
        # nothing either way (PSLFetcher does no I/O in __init__), but it makes
        # the guarantee local instead of something you have to trace the call
        # graph to confirm.
        self._psl_auto_update = bool(self.cfg["policy.psl_auto_update"])
        self._psl_fetcher = (
            PSLFetcher(self.http, self.log) if self._psl_auto_update else None
        )
        # Set by policy when the floor halt engages, so the refresh task can cut
        # its sleep short instead of waiting out a day-long timer after a
        # min_psl_version bump.
        self._psl_wake = asyncio.Event()
        # One-shot and local (no network): vendored copy plus any cached blob,
        # freshest wins.
        self._psl_holder = await self._load_psl_local()
        self.policy = PolicyManager(
            self.client,
            RoomID(self.cfg["policy_room"]),
            auto_config_type=self.cfg["auto_config_event_type"],
            max_writes_per_second=float(self.cfg["policy.max_writes_per_second"]),
            known_statuses=KNOWN_STATUSES,
            log=self.log,
            domain_statuses=self.db.statuses_for_domain,
            own_version=self._own_version(),
            psl_holder=self._psl_holder,
            on_psl_floor_halt=self._psl_wake.set,
            psl_auto_update=self._psl_auto_update,
        )
        # Both governance reads are attempted inline so a healthy start is
        # fully synchronous, exactly as before. Their success is remembered:
        # either failing leaves the policy layer HALTED (the rule fold is not
        # marked loaded, so no write can happen against an empty fold) and arms
        # the resync task below.
        self._governance_ok = await self.policy.load_rules()
        self._governance_ok &= await self.policy.refresh_auto_config()

        # Live governance-state handler, registered under the two SPECIFIC state
        # types it watches rather than @event.on(EventType.ALL). Under ALL,
        # mautrix schedules a task per ambient event (every message/receipt/
        # typing/membership in every joined room) just to run our isinstance
        # filter; registering the exact types means the dispatcher only ever
        # schedules us for these two. auto_config_type isn't known until here
        # (operator-configurable), hence runtime registration. We record the
        # exact (type, handler) pairs we added so stop() removes precisely
        # these -- auto_config_type can change across a config reload, so
        # removing by the live value could otherwise miss a stale registration.
        self._event_handler_regs: list[tuple[EventType, EventHandler]] = [
            (POLICY_RULE_SERVER, self._on_state_event),
            (self.policy.auto_config_type, self._on_state_event),
        ]
        for ev_type, handler in self._event_handler_regs:
            self.client.add_event_handler(ev_type, handler)

        # ingress sources
        self._sources: list[tuple[Source, int]] = []
        # textfiles: the only multi-instance source. List of independent pull
        # sources, each on its own clock, all feeding the same queue.
        for entry in (self.cfg["sources.textfiles"] or []):
            if not entry.get("enabled", True):
                continue
            url = entry.get("url")
            if not url:
                self.log.warning("skipping textfile source with no url",
                                 extra={"csreg_alarm": "textfile_no_url"})
                continue
            self._sources.append((
                TextFileSource(
                    url, self.http, self.log,
                    headers=entry.get("headers") or {},
                ),
                int(entry.get("interval_seconds", 3600)),
            ))
        self._pg: PostgresSource | None = None
        if self.cfg["sources.postgres.enabled"]:
            try:
                # Construction validates the query is SELECT-only and can raise;
                # connect can fail on a bad DSN. Either disables the source
                # rather than killing the plugin.
                self._pg = PostgresSource(
                    self.cfg["sources.postgres.dsn"],
                    self.cfg["sources.postgres.query"],
                    self.log,
                )
                await self._pg.connect()
                self._sources.append(
                    (self._pg, int(self.cfg["sources.postgres.interval_seconds"]))
                )
            except Exception as e:  # noqa: BLE001 -- don't let a bad DSN/query kill the plugin
                self.log.error("postgres source disabled: %s", e,
                               extra={"csreg_alarm": "postgres_connect_failed"})
                self._pg = None

        # Policy list as a source: re-verify domains already in the shared room.
        # No connect step -- it just reads policy's in-memory fold.
        if self.cfg["sources.policy_list.enabled"]:
            self._sources.append((
                PolicyListSource(self.policy, self.log),
                int(self.cfg["sources.policy_list.interval_seconds"]),
            ))

        # metrics server (own address, toggleable)
        self.metrics = None
        if self.cfg["metrics.enabled"]:
            self.metrics = MetricsServer(
                self.cfg["metrics.listen_host"],
                int(self.cfg["metrics.listen_port"]),
                self.cfg["metrics.path"],
                self.cfg["metrics.counts_path"],
                self._metrics_snapshot,
                self.log,
                expose_per_server=bool(self.cfg["metrics.expose_per_server"]),
            )
            await self.metrics.start()

        # background clocks
        if not self._governance_ok:
            self.log.error(
                "governance state incomplete at startup; policy writes are "
                "HALTED and will be retried every %ds", _GOVERNANCE_RETRY_SECONDS,
                extra={"csreg_alarm": "governance_resync_pending",
                       "retry_seconds": _GOVERNANCE_RETRY_SECONDS},
            )
            self._tasks.append(asyncio.create_task(self._governance_retry_loop()))
        if self._psl_auto_update:
            self._tasks.append(asyncio.create_task(self._psl_refresh_loop()))
        for source, interval in self._sources:
            self._tasks.append(asyncio.create_task(self._source_loop(source, interval)))
        if self.scanner is not None:
            self._tasks.append(asyncio.create_task(self._scan_loop()))
            self._tasks.append(asyncio.create_task(self._rescan_loop()))

        # Advertise our version in the bot's Matrix profile (best-effort; a
        # homeserver without MSC4133 custom-field support just rejects it).
        await self._publish_version()

        self.log.info("csreg started: %d source(s), scanner=%s, metrics=%s",
                      len(self._sources), bool(self.scanner), bool(self.metrics))

    async def _load_psl_local(self) -> PSLHolder:
        """Build the active suffix list from local sources only: the vendored
        copy, plus the cached blob from a previous fetch. Freshest VERSION wins.

        Deliberately NOT a retry loop, unlike the governance reads. Neither
        source fails transiently in a way retrying fixes: a missing cache row
        means there has never been a successful fetch, and an unreadable vendored
        copy is a packaging error. The online fetch is what recovers from
        transient conditions, and it has its own task.

        The cached blob is re-validated through the full gauntlet on read, even
        though it passed on the way in: a row outlives the code that wrote it, so
        it can have been hand-edited, restored from an old backup, or written by a
        version whose validation differed. A bad row is discarded in favour of
        vendored rather than adopted.

        Always returns a holder, EMPTY (current = None) when neither source
        yields a list. It must not raise: this runs inside start(), so an
        exception here kills the plugin outright -- which would be a hard block
        even for a deployment with no ban cap configured, where the suffix list is
        not used for anything. Degrading instead means such a bot starts normally
        with an alarm, a bot WITH a cap halts on the cap-and-no-list rule in
        reevaluate_psl_floor, and in both cases the refresh task can still adopt a
        fetched list and recover -- which it could not do through a holder that
        was never constructed.
        """
        vendored = None
        try:
            vendored = load_vendored_psl(log=self.log)
        except Exception as e:  # noqa: BLE001 -- packaging/IO failure
            self.log.error(
                "vendored public suffix list unavailable: %s", e,
                extra={"csreg_alarm": "psl_vendored_unavailable", "error": str(e)},
            )

        cached = None
        try:
            row = await self.db.get_cached_psl()
        except Exception as e:  # noqa: BLE001 -- DB read failure is not fatal here
            row = None
            self.log.warning("could not read cached public suffix list: %s", e)
        if row is not None:
            version_raw, _commit, body, fetched_at = row
            try:
                cached = validate_psl_text(body, source=f"cache (fetched {fetched_at})")
            except PSLValidationError as e:
                self.log.warning(
                    "cached public suffix list %s failed validation; ignoring it: %s",
                    version_raw, e,
                    extra={"csreg_alarm": "psl_cache_invalid",
                           "version": version_raw, "error": str(e)},
                )

        # Freshest wins. A cached copy older than vendored happens after a
        # package upgrade and is simply superseded, not an error.
        candidates = [p for p in (vendored, cached) if p is not None]
        if not candidates:
            self.log.error(
                "no public suffix list available from any local source; the "
                "per-eTLD+1 ban cap cannot be enforced until a fetch succeeds",
                extra={"csreg_alarm": "psl_unavailable"},
            )
            return PSLHolder(None, log=self.log)
        best = max(candidates, key=lambda p: p.version or datetime.min.replace(
            tzinfo=timezone.utc))
        self.log.info(
            "active public suffix list: %s", best.describe(),
            extra={"csreg_event": "psl_loaded", "psl_version": best.version_raw,
                   "psl_source": best.source},
        )
        return PSLHolder(best, log=self.log)

    async def _psl_refresh_loop(self) -> None:
        """Keep the suffix list fresh. Long-lived; cancelled by stop().

        Separate from the governance retry loop on purpose. That loop EXITS once
        room state is readable, treats failure as a halt, and retries every 60s --
        all three wrong here: freshness is a permanent concern, a fetch failure
        must NOT halt (we keep the list we have), and polling publicsuffix.org
        every minute from a fleet would earn a rate-limit and convert a freshness
        problem into an availability one.

        The first pass is skipped when the cached blob is already younger than the
        interval, so an on_external_config_update (stop+start) during a
        config-editing session does not produce a burst of fetches -- UNLESS the
        list is degraded, in which case a fresh cache is exactly what is not good
        enough and the fetch happens immediately.

        Cadence has two speeds. Healthy: daily. Degraded (no list, or below
        min_psl_version): _PSL_DEGRADED_RETRY_SECONDS, doubling toward daily. The
        doubling matters because "degraded" includes a floor no published list can
        satisfy -- a typo, or a stamp ahead of upstream -- where retrying forever
        at ten minutes would be a fleet-wide hammering of one volunteer-run host
        with no possible resolution. Any real progress (a newer list adopted) or a
        floor change resets it to the fast interval.
        """
        backoff = float(_PSL_DEGRADED_RETRY_SECONDS)
        if not self._psl_degraded() and await self._psl_cache_is_fresh(
                float(_PSL_REFRESH_SECONDS)):
            self.log.debug("cached public suffix list is fresh; deferring refresh")
            await self._psl_sleep(jittered_interval(float(_PSL_REFRESH_SECONDS)))
        while True:
            adopted = False
            try:
                adopted = await self._psl_refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 -- never let the clock die
                self.log.warning("public suffix list refresh error: %s", e)
            if self._psl_degraded():
                if adopted:
                    backoff = float(_PSL_DEGRADED_RETRY_SECONDS)
                interval = backoff
                backoff = min(backoff * 2, float(_PSL_REFRESH_SECONDS))
                self.log.info(
                    "public suffix list degraded (%s); retrying in %.0fs",
                    self.policy.halt_reason or "no list available", interval,
                    extra={"csreg_alarm": "psl_degraded",
                           "retry_seconds": round(interval)},
                )
            else:
                backoff = float(_PSL_DEGRADED_RETRY_SECONDS)
                interval = float(_PSL_REFRESH_SECONDS)
            if await self._psl_sleep(jittered_interval(interval)):
                # Woken by a floor change rather than the timer: treat it as fresh
                # trouble and start the ladder over, so a min_psl_version bump gets
                # the fast cadence even if we had already backed off.
                backoff = float(_PSL_DEGRADED_RETRY_SECONDS)

    def _psl_degraded(self) -> bool:
        """No list at all, or halted on the version floor -- i.e. a state a fetch
        could plausibly fix. Note the no-list case is checked independently of the
        cap: with no cap the bot is not halted, but it still has no list and
        should keep trying to get one."""
        no_list = self._psl_holder is None or self._psl_holder.current is None
        return no_list or self.policy.psl_floor_halted

    async def _psl_sleep(self, seconds: float) -> bool:
        """Sleep, returning early if the floor halt engages. True if woken."""
        try:
            await asyncio.wait_for(self._psl_wake.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            return False
        self._psl_wake.clear()
        self.log.debug("public suffix list refresh woken by a floor change")
        return True

    async def _psl_cache_is_fresh(self, interval: float) -> bool:
        try:
            row = await self.db.get_cached_psl()
        except Exception:  # noqa: BLE001
            return False
        return row is not None and (now() - row[3]) < interval

    async def _psl_refresh_once(self) -> bool:
        """One fetch/validate/adopt cycle. Returns whether a newer list was
        adopted, which the caller uses to decide whether it made progress."""
        if self._psl_fetcher is None:
            # Unreachable: the loop that calls this is only started when
            # auto-update is on. Defensive, so a future caller cannot turn a
            # disabled fetcher into an AttributeError.
            return False
        outcome = await self._psl_fetcher.fetch()
        if outcome.not_modified:
            self.log.debug("public suffix list unchanged upstream (304)")
            return False
        if outcome.psl is None:
            # WARNING, not ERROR: we still have a usable list. Whether that list
            # is ACCEPTABLE is decided by the floor, not here.
            self.log.warning(
                "public suffix list refresh failed: %s", outcome.error,
                extra={"csreg_alarm": "psl_refresh_failed",
                       "error": outcome.error,
                       "active_version": self._psl_holder.version_raw},
            )
            return False
        if not self._psl_holder.adopt(outcome.psl):
            self.log.debug(
                "fetched public suffix list %s is not newer than active %s; kept",
                outcome.psl.version_raw, self._psl_holder.version_raw,
            )
            return False
        try:
            await self.db.put_cached_psl(
                outcome.psl.version_raw or "", outcome.psl.commit,
                outcome.psl.raw_text,
            )
        except Exception as e:  # noqa: BLE001 -- adoption already happened
            # Persist failure is not a rollback: the newer list is already active
            # and correct. The only cost is that a restart before the next
            # successful fetch falls back to vendored.
            self.log.warning("could not cache public suffix list: %s", e)
        # A newer list can clear (or, after a floor bump, newly satisfy) the
        # suffix-list halt. This is the second of the two callers -- the other is
        # _apply_auto_config when min_psl_version moves.
        self.policy.reevaluate_psl_floor()
        return True

    async def _governance_retry_loop(self) -> None:
        """Re-read governance state until both halves land, then exit.

        Scanning continues throughout -- results are still recorded, the queue
        still drains -- but the policy layer stays halted, so nothing is written
        to the list while we cannot see what is already on it. Exits (rather than
        looping forever) once both reads succeed, because from then on the live
        state-event handler keeps both current.

        Only READ failures are retried. A successful read of an absent or
        malformed auto_config returns True from refresh_auto_config: the bot stays
        halted, but the fix is an operator edit and the state-event handler will
        pick that up the moment it happens, so spinning here would only produce
        an error line every 60s for a room that is legitimately mid-setup.
        """
        while True:
            await asyncio.sleep(_GOVERNANCE_RETRY_SECONDS)
            try:
                rules_ok = await self.policy.load_rules()
                config_ok = await self.policy.refresh_auto_config()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("governance resync error: %s", e)
                continue
            if rules_ok and config_ok:
                self._governance_ok = True
                self.log.info(
                    "governance state resynced (%d rule(s) in fold); halted=%s",
                    self.policy.active_rules(), self.policy.halted,
                    extra={"csreg_event": "governance_resynced"},
                )
                return
            self.log.error(
                "governance resync failed; policy writes still halted (%s), "
                "retrying in %ds", self.policy.halt_reason,
                _GOVERNANCE_RETRY_SECONDS,
                extra={"csreg_alarm": "governance_resync_failed",
                       "reason": self.policy.halt_reason},
            )

    def _own_version(self) -> str | None:
        """This plugin's version as a plain string, straight from maubot.yaml via
        the loader metadata.

        Two consumers: the MSC4133 profile advertisement below (so an operator can
        SEE fleet versions) and policy.PolicyManager's min_bot_version floor (so
        the operator can ENFORCE one). Both must read the same value or the
        profile would advertise something different from what the gate compares.
        The loader may hand back a packaging Version object rather than a str, so
        stringify here and let the policy layer parse it.
        """
        meta = getattr(self, "loader", None)
        version = getattr(getattr(meta, "meta", None), "version", None)
        return str(version) if version else None

    async def _publish_version(self) -> None:
        """Best-effort: advertise this plugin's version in the bot's own Matrix
        profile via an MSC4133 custom profile field, so a list operator can see
        which version each contributing bot is running just by looking at its
        profile.

        The field name follows the Common Namespaced Identifier Grammar the 
        server enforces on custom fields.
        """
        version = self._own_version()
        if not version:
            self.log.warning(
                "could not determine plugin version; skipping profile publish",
                extra={"csreg_alarm": "version_publish_no_version"},
            )
            return
        version_str = version
        try:
            await self.client.api.request(
                Method.PUT,
                Path.v3.profile[self.client.mxid][_VERSION_PROFILE_FIELD],
                content={_VERSION_PROFILE_FIELD: version_str},
            )
        except Exception as e:  # noqa: BLE001 -- profile publish must never break startup
            self.log.warning(
                "could not publish version to profile (homeserver may lack "
                "MSC4133 custom-field support): %s", e,
                extra={"csreg_alarm": "version_publish_failed",
                       "version": version_str},
            )
            return
        self.log.info(
            "published version %s to profile field %s",
            version_str, _VERSION_PROFILE_FIELD,
            extra={"csreg_event": "version_published", "version": version_str},
        )

    async def stop(self) -> None:
        # Unregister the runtime-registered state handlers first, so a config
        # reload (stop() then start()) can't stack duplicate registrations or
        # leave one bound to a now-stale auto_config type. Remove exactly the
        # (type, handler) pairs start() recorded. getattr guards a stop() that
        # runs before/without a completed start().
        for ev_type, handler in getattr(self, "_event_handler_regs", []):
            self.client.remove_event_handler(ev_type, handler)
        self._event_handler_regs = []

        for t in getattr(self, "_tasks", []):
            t.cancel()
        # Cancel any fire-and-forget scans still running from the last tick.
        inflight = list(getattr(self, "_inflight", {}).values())
        for t in inflight:
            t.cancel()
        pending = list(getattr(self, "_tasks", [])) + inflight
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if self._pg is not None:
            await self._pg.close()
        if self.metrics is not None:
            await self.metrics.stop()
        # Close the scanner's owned resources before the shared client. The
        # scanner does NOT own the injected self._http_client (its aclose() is a
        # no-op for that), but the federation version probe keeps its OWN
        # verify-disabled client internally -- scanner.aclose() is the only thing
        # that closes it, so skipping this leaks that client + its pool on every
        # stop()/config reload.
        if getattr(self, "scanner", None) is not None:
            await self.scanner.aclose()
        # Close the shared aiohttp client last, after all in-flight scans that
        # borrow it have been cancelled and awaited above.
        if getattr(self, "_http_client", None) is not None:
            await self._http_client.close()

    async def on_external_config_update(self) -> None:
        """maubot calls this when the instance config is edited. Nothing here is
        live-reloadable in place (loops capture intervals, _staleness is built at
        start, the metrics socket is already bound), so the robust move is a full
        teardown + rebuild: stop() cancels every loop and in-flight scan, closes
        the pg source and the metrics listener; start() re-reads the YAML and
        rebinds everything. Brief scan interruption + metrics-socket rebind is
        the accepted cost. BOTH halves are guarded: an exception in stop() must
        not block the rebuild, and an exception in start() (bad YAML value, a
        metrics port grabbed by another process, ...) must not leave a silently
        half-built instance -- on start() failure we tear down whatever it
        managed to build (stop() is getattr-guarded everywhere, so it is safe
        against partial state) and leave the plugin DOWN with a loud structured
        alarm, rather than down with nothing but a swallowed traceback."""
        self.log.info("config changed; restarting plugin runtime")
        try:
            await self.stop()
        except Exception as e:  # noqa: BLE001
            self.log.warning("error during config-reload stop(): %s", e)
        try:
            await self.start()
        except Exception as e:
            self.log.exception(
                "config reload failed in start(); plugin is NOT running until "
                "the next successful config edit or maubot restart",
                extra={"csreg_alarm": "config_reload_failed", "error": str(e)},
            )
            # Best-effort teardown of whatever the failed start() half-built
            # (loops, sockets, sessions), so nothing orphaned keeps running.
            try:
                await self.stop()
            except Exception as e2:  # noqa: BLE001
                self.log.warning("cleanup after failed start() also failed: %s", e2)

    # --- ingress -------------------------------------------------------------

    async def _source_loop(self, source: Source, interval: int) -> None:
        while True:
            try:
                await self._ingest(source)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("source %s fetch failed: %s", source.name, e)
            await asyncio.sleep(interval)

    async def _ingest(self, source: Source) -> None:
        raw = await source.fetch()
        domains = self._clean(raw)
        await self.db.enqueue(domains)
        if domains:
            self.log.debug("source %s ingested %d candidate(s)", source.name, len(domains))

    def _clean(self, raw: list[Any]) -> list[str]:
        """Validate and de-dupe a batch of raw names into scan targets.

        We keep the FULL server-name (with port if present) as the scan target:
        the port is load-bearing for the scanner (regcheck does federation
        resolution on the full name, and matrix.org vs matrix.org:8448 can have
        different registration behaviour). Port-stripping happens later and only
        for the policy-rule key / unban-guard grouping (db.record_scan derives
        the portless `domain`); it must NOT happen here at ingest.

        Dedup is therefore on the full target too, matching scan_queue's PK.
        """
        out: list[str] = []
        seen: set[str] = set()
        for name in raw:
            # The webhook JSON path can hand us non-strings (e.g. {"servers":
            # [123]}); skip them rather than crashing the request.
            if not isinstance(name, str):
                continue
            name = name.strip()
            if not name or not validate_server_name(name):
                continue
            if name not in seen:
                seen.add(name)
                out.append(name)
        return out

    async def _on_state_event(self, evt: StateEvent) -> None:
        """Keep in-memory governance state live without polling. Registered at
        runtime (start()) under exactly two specific state EventTypes -- NOT
        @event.on(EventType.ALL) -- so mautrix's dispatch table only schedules
        this handler for those types, instead of spawning a task per ambient
        event (every message/receipt/typing/membership in every joined room) to
        run an isinstance filter. The auto_config type is operator-configurable
        and only known at start(), which is why this is registered there via
        client.add_event_handler rather than decorated.

        Two surfaces, both in the policy room:
          * m.policy.rule.server -> keep the local rule fold current as OTHER
            writers change the room (another operator's bot, the self-service
            bot, a manual ban). Without it our fold goes stale and we re-send
            already-applied bans/tombstones.
          * auto_config -> re-validate governance config the moment the operator
            edits it, instead of re-reading it on every scan/rescan tick (that
            was a homeserver round-trip on a hot path; now it's read once at
            start() and refreshed only on change).

        Type routing is now done by the dispatcher, but we still filter by room
        (handlers are registered globally across rooms, just not across types)
        and keep a defensive isinstance guard.
        """
        if not isinstance(evt, StateEvent):
            return  # type: ignore[unreachable]
        # A config reload tears down (stop()) and rebuilds (start()) the plugin.
        # remove_event_handler unhooks us from the dispatch table, but mautrix
        # may already have SCHEDULED this coroutine (background_task.create) for
        # an event that arrived just before the reload -- that scheduled task is
        # not recalled. It can therefore run in the window where self.policy has
        # been torn down and not yet reassigned. No state is lost by skipping:
        # start() does a fresh load_rules()+refresh_auto_config(), so the room is
        # re-read in full on the way back up.
        policy = getattr(self, "policy", None)
        if policy is None:
            return
        if evt.room_id != policy.room_id:
            return
        if evt.type == POLICY_RULE_SERVER:
            policy.note_rule(evt.state_key, evt.content)
        elif evt.type == policy.auto_config_type and evt.state_key == "":
            policy.apply_auto_config_event(evt.content)

    @web.post("/ingest")  # type: ignore[arg-type]
    async def webhook_ingest(self, req: Request) -> Response:  # type: ignore[misc]
        """Push ingress. Body: newline/space-separated names, or
        JSON {"servers": [...]}."""
        if not self.cfg["sources.webhook.enabled"]:
            return Response(status=404)
        secret = self.cfg["sources.webhook.secret"]
        auth = req.headers.get("Authorization", "")
        # Constant-time compare to avoid leaking the secret via timing. An empty
        # configured secret hard-fails closed (never treat "" as open).
        #
        # Compared as BYTES: hmac.compare_digest raises TypeError on str inputs
        # containing non-ASCII, and aiohttp decodes header values as latin-1, so
        # any raw byte >= 0x80 in the Authorization header used to reach it as a
        # non-ASCII str and turn an unauthenticated request into a 500 with a
        # traceback instead of a 401. surrogateescape round-trips whatever
        # arrived without raising.
        expected = f"Bearer {secret}".encode()
        provided = auth.encode("utf-8", "surrogateescape")
        if not secret or not hmac.compare_digest(provided, expected):
            return Response(status=401)
        body = await req.text()
        # Accept JSON {"servers": [...]}, a bare JSON list, or whitespace-
        # separated names. _clean drops anything that isn't a valid name.
        names: list[str]
        try:
            parsed = json.loads(body)
        except ValueError:
            names = body.split()
        else:
            if isinstance(parsed, dict):
                names = parsed.get("servers", []) or []
            elif isinstance(parsed, list):
                names = parsed
            else:
                names = []
        cleaned = self._clean(names)
        await self.db.enqueue(cleaned)
        return Response(text=f"accepted {len(cleaned)}\n")

    # --- config calculator ---------------------------------------------------
    # Stateless helper UI: reads ONLY the local /counts JSON (never /metrics,
    # so the server list never transits this path), lets the operator edit the
    # per-bucket staleness T and a safety factor, and emits a copy-pasteable
    # config block. The browser talks only to this maubot web base path; the
    # metrics port stays bound to 127.0.0.1 and is never browser-reachable.

    def _counts_url(self) -> str:
        host = self.cfg["metrics.listen_host"] or "127.0.0.1"
        # A 0.0.0.0/:: listen host isn't a valid *connect* target; loop back.
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = int(self.cfg["metrics.listen_port"])
        path = self.cfg["metrics.counts_path"]
        return f"http://{host}:{port}{path}"

    @web.get("/calc/data")  # type: ignore[arg-type]
    async def calc_data(self, _req: Request) -> Response:  # type: ignore[misc]
        """Server-side fetch of the local /counts only. Pass-through to the
        browser so the metrics port need not be reachable from the client and
        no server list is ever pulled (we deliberately do NOT touch /metrics)."""
        if not self.cfg["metrics.enabled"]:
            return Response(status=503, text='{"error":"metrics disabled"}',
                            content_type="application/json")
        url = self._counts_url()
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as sess, sess.get(url) as resp:
                if resp.status != 200:
                    return Response(
                        status=502,
                        text=json.dumps({"error": f"counts {resp.status}"}),
                        content_type="application/json",
                    )
                body = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return Response(status=502, text=json.dumps({"error": str(e)}),
                            content_type="application/json")
        # Echo the counts payload verbatim; the math lives client-side.
        return Response(text=body, content_type="application/json")

    @web.get("/calc")  # type: ignore[arg-type]
    async def calc_page(self, _req: Request) -> Response:  # type: ignore[misc]
        """Self-hosted calculator UI. The page is a static asset shipped in the
        package (csreg_scanner/web/calc.html) -- no external assets (DSGVO): all
        CSS/JS inline, system font stack only. Loaded once and cached in
        memory."""
        return Response(text=_load_calc_html(), content_type="text/html",
                        charset="utf-8")


    # --- scan tick (drains the queue, -----------------------------------------

    async def _scan_loop(self) -> None:
        interval = int(self.cfg["queue.scan_interval_seconds"])
        limit = int(self.cfg["queue.scan_batch_limit"])
        # Lease window for a claimed queue row. The scan itself can't run past
        # the scanner timeout, but the lease clock starts at the CLAIM, and
        # under load there is real time between claim and task start (event-
        # loop lag with hundreds of tasks) plus the terminal DB write at the
        # end -- +1s of slack was tight enough that a delayed terminal write
        # could expire the lease under a still-running scan. 30s of slack
        # costs nothing in the crash-recovery case (the only case the lease is
        # for: a premature expiry is additionally harmless now, because the
        # in-flight guard turns a re-claimed running target into a skip, never
        # a duplicate launch).
        lease_seconds = int(float(self.cfg["scanner.timeout_seconds"])) + 30
        while True:
            try:
                # Admission gate: only claim as many rows as there are free
                # in-flight slots. Unclaimed rows keep leased_until NULL and
                # are picked up by a later tick -- deferral, not queuing, so
                # nothing waits with its lease burning invisibly.
                slots = self._max_inflight - len(self._inflight)
                if slots <= 0:
                    self._admission_deferred("scan")
                else:
                    pending = await self.db.pending(min(limit, slots), lease_seconds)
                    for target in pending:
                        self._launch_scan(target, "scan")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("scan tick error: %s", e)
            await asyncio.sleep(interval)

    # --- rescan tick (most-overdue,) ---------------------------------------------

    async def _rescan_loop(self) -> None:
        interval = int(self.cfg["rescan.interval_seconds"])
        limit = int(self.cfg["rescan.batch_limit"])
        while True:
            try:
                buckets = await self.db.bucket_counts()
                self._capacity_alarm_from(buckets)

                # Leaky-bucket meter: accrue demand-proportional credit, clamp so
                # idle periods can't hoard a burst, then take at most floor(credit)
                # this tick (never more than batch_limit). This spreads rescans at
                # the long-run required rate instead of dumping the whole overdue
                # set the instant deadlines cross.
                required = self._required_rate(buckets)
                self._rescan_credit = min(
                    float(limit), self._rescan_credit + required * interval
                )
                want = min(int(self._rescan_credit), limit)
                # Admission gate: cap this tick's take by free in-flight slots.
                # Withheld credit is NOT forfeited (only launched work spends
                # credit, below), so deferred demand carries to the next tick.
                slots = self._max_inflight - len(self._inflight)
                take = min(want, max(slots, 0))
                if want >= 1 and take < want:
                    self._admission_deferred("rescan", deferred=want - take)
                if take >= 1:
                    # Over-fetch by the in-flight count: a target already being
                    # scanned is skipped by _launch_scan (duplicate guard), and
                    # without the over-fetch those skips would mask genuinely-
                    # due rows ranked just below them in the staleness order.
                    due = await self.db.most_overdue(
                        self._staleness, take + len(self._inflight)
                    )
                    launched = 0
                    for target in due:
                        if launched >= take:
                            break
                        if self._launch_scan(target, "rescan"):
                            launched += 1
                    # Spend credit only for scans actually LAUNCHED: skipped
                    # duplicates and shorter-than-authorized overdue lists keep
                    # their budget so newly-due servers are picked up promptly
                    # rather than forfeiting it.
                    self._rescan_credit -= launched
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("rescan tick error: %s", e)
            await asyncio.sleep(interval)

    # --- shared scan unit ----------------------------------------------------

    def _launch_scan(self, scan_target: str, kind: str) -> bool:
        """Fire a scan as a tracked background task, unless one for this exact
        target is already in flight. The tick does NOT await it: each tick
        launches its admitted batch and returns to its fixed-rate clock; total
        concurrency is bounded by _max_inflight via the admission gates in the
        two tick loops. Tracked in _inflight (keyed by target) so the task
        can't be GC'd mid-run AND so the same target can never run twice
        concurrently; the done-callback logs failures and unregisters it.

        Returns True when a task was launched, False when the target was
        skipped because it is already being scanned -- callers use this to
        account only for real launches (rescan credit)."""
        if scan_target in self._inflight:
            # Already running: a rescan tick re-picked a slow target whose
            # terminal write hasn't landed yet, or a queue lease expired under
            # a still-running scan. Skip -- the running scan's terminal write
            # covers this demand.
            return False
        task = asyncio.create_task(self._scan_one(scan_target))
        self._inflight[scan_target] = task
        task.add_done_callback(lambda t: self._scan_done(t, kind, scan_target))
        return True

    def _scan_done(self, task: asyncio.Task[None], kind: str, scan_target: str) -> None:
        self._inflight.pop(scan_target, None)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self.log.warning(
                "%s task raised: %s", kind, exc,
                extra={"csreg_alarm": f"{kind}_task_error"},
            )

    def _admission_deferred(self, kind: str, deferred: int | None = None) -> None:
        """Loud, structured signal that the in-flight ceiling deferred launches
        this tick. Deferral is designed behavior -- the work is retried on the
        next tick (queue rows stay claimable, rescan credit is retained) -- but
        it must never be invisible: persistent saturation means scans complete
        slower than launch demand, and the operator should learn that from this
        alarm (and the csreg_scans_inflight gauge), not from mysteriously stale
        buckets. Fires at most once per tick per loop."""
        extra = {
            "csreg_alarm": "scan_admission_deferred",
            "kind": kind,
            "inflight": len(self._inflight),
            "ceiling": self._max_inflight,
            "hint": "scans complete slower than launch demand; if persistent, "
                    "investigate slow/dead targets or raise the batch limits "
                    "(the ceiling is queue.scan_batch_limit + rescan.batch_limit)",
        }
        if deferred is not None:
            extra["deferred"] = deferred
        self.log.warning(
            "%s launches deferred: in-flight scans at ceiling (%d/%d)",
            kind, len(self._inflight), self._max_inflight, extra=extra,
        )

    async def _scan_one(self, scan_target: str) -> None:
        # Bind the target for this scan so every line logged from here down the
        # scanner call stack carries scan_target on the record.
        # Task-scoped -- this coroutine runs as its own task, so no reset needed.
        bind_scan_target(scan_target)
        t0 = time.monotonic()
        result, version, support = await self.scanner.scan(scan_target)
        dt = time.monotonic() - t0
        # EWMA kept for metrics only -- it no longer influences any setting.
        self._avg_scan = (1 - _EWMA_ALPHA) * self._avg_scan + _EWMA_ALPHA * dt
        # terminal write happens regardless of ok/fail (anti-wedge). The version
        # carries its own authoritative flag: a non-authoritative probe preserves
        # any previously stored version rather than wiping it. The returned record
        # tells us whether reg_status transitioned (drives the log level below).
        record = await self.db.record_scan(
            scan_target,
            ok=result.ok,
            status=result.status,
            fed_observed=version.authoritative,
            fed_name=version.name,
            fed_version=version.version,
        )

        # Support well-known: write ONLY an authoritative fetch (200 + JSON
        # object). Everything else -- 404, blank/HTML page, network error,
        # oversize, or the phase being skipped/disabled -- performs no write, so
        # prior stored data survives (overwrite-only-on-good-JSON, mirroring the
        # fed_* preserve rule but via write-omission instead of SQL CASE).
        # Keyed on the portless domain: the well-known lives on the origin, so
        # every port-variant target of a domain maps to the same document.
        if support.authoritative and support.raw_json is not None:
            await self.db.record_support(strip_port(scan_target), support.raw_json)

        # Per-scan result log. Structured fields are ALWAYS present in extra
        # (null where N/A) for a future JSON log shipper, but our current pipeline
        # forwards only the MESSAGE TEXT, so the human-facing facts are also 
        # embedded in the message as logfmt key=value pairs for key-value extraction. 
        #
        # Level: a reg-status transition -- including the first-ever sighting of
        # a target (previous_status None) -- is INFO so it surfaces in the maubot
        # web log. A federation-version transition (record.version_changed) is
        # ALSO INFO, even when the reg_status is unchanged, so version rollouts
        # surface the same way status flips do. When BOTH move in one scan they
        # share a single combined INFO line. An otherwise-unchanged status is
        # DEBUG (the steady-state rescan firehose stays out of INFO). A
        # task-failure is not a transition and stays DEBUG too; it carries the
        # (quoted) error instead of version keys, since the version probe is
        # skipped when the reg-scan fails.
        prev_name, prev_version = (
            record.previous_version if record.previous_version else (None, None)
        )
        # A non-authoritative probe PRESERVES the stored pair (db.record_scan's
        # CASE on fed_observed), so the row's value after this write is the
        # previous one, not the probe's empty fields. Compute the stored pair
        # once here and report THAT everywhere below.
        stored_name = version.name if version.authoritative else prev_name
        stored_version = version.version if version.authoritative else prev_version
        extra = {
            "csreg_event": "scan_result",
            "scan_target": scan_target,
            "reg_status": result.status,
            "previous_status": record.previous_status,
            "fed_name": stored_name,
            "fed_version": stored_version,
            "previous_fed_name": prev_name,
            "previous_fed_version": prev_version,
            # The raw probe outcome, kept as separate fields so the distinction
            # between "server reported nothing this scan" and "we have nothing
            # stored" survives into the structured log.
            "fed_probe_authoritative": version.authoritative,
            "fed_probe_name": version.name,
            "fed_probe_version": version.version,
        }
        # logfmt rendering of the version pair, shared by the change/unchanged
        # lines. A null name/version renders as "-" (kept out of the message as
        # the literal None so it can't collide with a real value).
        #
        # This reports the STORED pair, not the probe result. Rendering the
        # probe's empty fields made a PRESERVED value look like it had been
        # wiped: an `open -> unknown` transition logged "name=- version=-" even
        # though the row still held Synapse/1.157.2 untouched. `version_probe=
        # none` is appended in that case so the line says why the pair did not
        # come from this scan, rather than silently implying it did.
        ver_kv = (
            f"name={stored_name if stored_name is not None else '-'} "
            f"version={stored_version if stored_version is not None else '-'}"
        )
        if not version.authoritative:
            ver_kv += " version_probe=none"
        # Version transition rendered as an old -> new pair, joined name/version
        # so "Synapse/1.96.0 -> Synapse/1.97.0" reads as one token per side. A
        # null side renders "-" (e.g. first authoritative sighting: "- -> ...").
        def _ver_side(name: str | None, ver: str | None) -> str:
            n = name if name is not None else "-"
            v = ver if ver is not None else "-"
            return f"{n}/{v}"
        ver_change_kv = (
            f"{_ver_side(prev_name, prev_version)} -> "
            f"{_ver_side(version.name, version.version)}"
        )
        if not result.ok:
            extra["scan_error"] = result.error
            # Quote the free-text error and neutralize any inner double-quotes so
            # error="..." stays a single well-formed key=value for the extractor.
            err = (result.error or "").replace('"', "'")
            self.log.debug(
                'scan failed for %s: error="%s"', scan_target, err, extra=extra
            )
        elif record.changed and record.version_changed:
            # Both moved this scan -- one combined INFO line.
            self.log.info(
                "reg-status + version change for %s: %s -> %s | version %s",
                scan_target, record.previous_status, result.status,
                ver_change_kv, extra=extra,
            )
        elif record.changed:
            self.log.info(
                "reg-status change for %s: %s -> %s %s",
                scan_target, record.previous_status, result.status, ver_kv,
                extra=extra,
            )
        elif record.version_changed:
            self.log.info(
                "version change for %s: %s (status %s unchanged)",
                scan_target, ver_change_kv, result.status,
                extra=extra,
            )
        else:
            self.log.debug(
                "scan for %s: %s (unchanged) %s",
                scan_target, result.status, ver_kv,
                extra=extra,
            )

        if result.ok and result.status is not None:
            # same shared policy-write path for scan + rescan
            await self.policy.reconcile(scan_target, result.status)
            # Stale-entry cleanup runs AFTER reconcile, on the same result, so a
            # target that just moved off `unknown` is reconciled normally and
            # never considered stale in the same pass. status_since comes back
            # from the write we already did, so this costs no extra query. The
            # `scanned` row is deliberately left intact -- this is policy-list
            # hygiene only, and the history is kept for stats. Each removal is
            # recorded by the structured stale_cleanup log line.
            await self.policy.consider_stale_cleanup(
                scan_target, result.status, record.status_since
            )

    # --- observability ----------------------------------------------------------

    def _rates(self, buckets: dict[str, int]) -> tuple[float, float]:
        # Required rescan rate = sum(N_bucket / T_bucket) servers/sec. Achievable
        # rate is now pure throughput -- batch_limit launched per interval -- and
        # no longer depends on measured scan duration (durations are too dynamic
        # to drive config; they stay as metrics only). required > achievable is
        # the "falling behind on staleness" signal.
        required = self._required_rate(buckets)
        interval = int(self.cfg["rescan.interval_seconds"])
        batch = int(self.cfg["rescan.batch_limit"])
        achievable = batch / interval if interval > 0 else 0.0
        return required, achievable

    def _required_rate(self, buckets: dict[str, int]) -> float:
        """Demand in scans/sec to keep every bucket within its staleness T:
        sum(N_bucket / T_bucket). Shared by the capacity alarm and the rescan
        rate-meter so they can never disagree."""
        default_t = self._staleness.get("unknown", _DEFAULT_STALENESS_SECONDS)
        return sum(
            n / self._staleness.get(status, default_t)
            for status, n in buckets.items()
        )

    def _capacity_alarm_from(self, buckets: dict[str, int]) -> None:
        # Takes pre-fetched counts so the rescan loop (and the metrics snapshot)
        # don't run a second bucket_counts() just to emit the saturation signal.
        required, achievable = self._rates(buckets)
        if required > achievable:
            self.log.warning(
                "rescan demand exceeds capacity",
                extra={
                    "csreg_alarm": "rescan_saturation",
                    "required_rate": round(required, 6),
                    "achievable_rate": round(achievable, 6),
                    "hint": "raise rescan.batch_limit, shorten rescan."
                            "interval_seconds, or relax T for the largest bucket",
                },
            )

    async def _metrics_snapshot(self) -> dict[str, Any]:
        # Skip the full scanned-table read when per-server series are disabled;
        # nothing else consumes `servers`, and bucket_counts is a cheap GROUP BY.
        if self.cfg["metrics.expose_per_server"]:
            servers = await self.db.all_statuses()
        else:
            servers = []
        buckets = await self.db.bucket_counts()
        total = sum(buckets.values())
        queue_depth = await self.db.queue_depth()
        initial_scans, rescans, total_scans = await self.db.scan_totals()
        # Nominal queue-drain throughput = scan_batch_limit / scan_interval.
        # Pure config (a flat reference line between reloads), NOT a guarantee:
        # the admission ceiling is shared with the rescan path, so under
        # saturation the ACTUAL initial rate (rate() over the initial type of
        # the by-type counter) sits below this even with a full queue -- that
        # gap, alongside a nonzero queue depth, is the queue-path saturation
        # signal (paired with the scan_admission_deferred alarm saying why).
        q_interval = int(self.cfg["queue.scan_interval_seconds"])
        q_batch = int(self.cfg["queue.scan_batch_limit"])
        initial_achievable = q_batch / q_interval if q_interval > 0 else 0.0
        required, achievable = self._rates(buckets)
        fed_versions = await self.db.fed_version_counts()
        support_total, support_reachable = await self.db.support_coverage()
        return {
            "servers": servers,
            "buckets": buckets,
            "total": total,
            "total_scans": total_scans,
            "initial_scans": initial_scans,
            "rescans": rescans,
            "queue_depth": queue_depth,
            "active_rules": self.policy.active_rules(),
            "halted": self.policy.halted,
            "cleanup_enabled": self.policy.cleanup_enabled,
            "ban_cap_enabled": self.policy.max_bans_per_etld1 is not None,
            "etld1s_at_cap": self.policy.etld1s_at_cap,
            # Suffix-list state. Exposed HERE and only here -- deliberately NOT in
            # the MSC4133 profile field. The profile is world-readable, and
            # advertising which bot is running an outdated list tells an attacker
            # exactly which one to aim unbounded bans at. The metrics endpoint is
            # loopback-bound, so this stays moderator-visible.
            "psl_version": (self._psl_holder.version_raw
                            if self._psl_holder is not None else None),
            "psl_source": (self._psl_holder.current.source
                           if self._psl_holder is not None
                           and self._psl_holder.current is not None else None),
            "psl_min_version": self.policy.min_psl_version_raw,
            "psl_floor_ok": not bool(self.policy._psl_halt_reason),
            "avg_scan": self._avg_scan,
            "inflight": len(self._inflight),
            "inflight_ceiling": self._max_inflight,
            "required_rate": required,
            "achievable_rate": achievable,
            "initial_achievable_rate": initial_achievable,
            # Config-as-metric block: static between reloads, exposed so
            # dashboards/alerts can reference the settings (threshold lines,
            # joins) instead of hardcoding them. Staleness comes from the
            # validated map (self._staleness), not raw config, so the exposed
            # values are the ones the rescan loop actually uses.
            "staleness": dict(self._staleness),
            "loop_config": {
                "initial": {
                    "interval": q_interval,
                    "batch_limit": q_batch,
                },
                "rescan": {
                    "interval": int(self.cfg["rescan.interval_seconds"]),
                    "batch_limit": int(self.cfg["rescan.batch_limit"]),
                },
            },
            "scan_timeout": float(self.cfg["scanner.timeout_seconds"]),
            "fed_versions": fed_versions,
            # Support-document coverage. Domain-granular (support_info is keyed
            # on the portless domain), unlike every other count here, which is
            # scan_target-granular -- see db.support_coverage.
            "support_total": support_total,
            "support_reachable": support_reachable,
        }
