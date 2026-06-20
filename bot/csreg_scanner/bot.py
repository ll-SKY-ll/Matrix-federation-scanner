"""net.codestorm.csreg -- decentralized open-registration scanner.

Main plugin: orchestrates ingress clocks, the queue-draining scan tick, the
most-overdue rescan tick, policy governance, and the metrics server.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import pkgutil
import time

import aiohttp
import httpx
from aiohttp.web import Request, Response
from maubot import Plugin
from maubot.handlers import web
from mautrix.client import EventHandler
from mautrix.types import EventType, RoomID, StateEvent
from mautrix.util.async_db import UpgradeTable

from .config import Config
from .db import DB, upgrade_table
from .metrics import MetricsServer
from .policy import POLICY_RULE_SERVER, PolicyManager
from .regcheck import Scanner
from .sources import PolicyListSource, PostgresSource, Source, TextFileSource
from .taxonomy import KNOWN_STATUSES
from .util import validate_server_name

# EWMA weight for the rolling average scan duration.
_EWMA_ALPHA = 0.2

# -- Calculator UI --------------------------------------------------------------
# The page itself lives in csreg_scanner/web/calc.html (shipped as an extra_file
# and loaded via pkgutil so it works from inside the .mbp zip, same pattern as
# the scanner binary). Self-contained: inline CSS/JS, system font stack, no
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
    metrics: MetricsServer | None

    @classmethod
    def get_config_class(cls) -> type[Config]:
        return Config

    @classmethod
    def get_db_upgrade_table(cls) -> UpgradeTable | None:
        return upgrade_table

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        self.config.load_and_update()
        self.db = DB(self.database)

        self._tasks: list[asyncio.Task] = []
        self._avg_scan: float = 5.0  # seed; refined by EWMA (metrics only)
        # Fire-and-forget scan tasks live here so the GC can't collect a running
        # scan mid-flight (asyncio only weak-refs tasks), exceptions still get
        # logged via a done-callback, and stop() can cancel anything in flight.
        self._inflight: set[asyncio.Task] = set()

        # Rescan rate-meter (leaky bucket). Each tick we add required_rate*interval
        # "credits" and launch floor(credit) most-overdue servers, so the long-run
        # scan rate matches demand (sum N_b/T_b) instead of bursting the entire
        # overdue set the instant deadlines cross. In-memory: resets to 0 on
        # restart and re-converges within a few ticks.
        self._rescan_credit: float = 0.0

        # Per-status staleness T (seconds), sanitized once. Keys are interpolated
        # into SQL by db.most_overdue, so drop anything that isn't a known status
        # here -- this both prevents bad SQL and surfaces config typos (a typo'd
        # bucket would otherwise silently fall through to the default T).
        self._staleness: dict[str, int] = {}
        for status, secs in dict(self.config["rescan.staleness_seconds"] or {}).items():
            if status not in KNOWN_STATUSES:
                self.log.warning(
                    "rescan.staleness_seconds: ignoring unknown status %r", status,
                    extra={"csreg_alarm": "staleness_unknown_status", "key": status},
                )
                continue
            self._staleness[status] = int(secs)

        # scanner: in-process registration checker over a shared httpx client.
        # The client is pooled across all scans and closed in stop(); the
        # Scanner does not own it (aclose() is a no-op for an injected client).
        # Timeouts: 3s connect (a dead address -- e.g. a stale AAAA on an
        # otherwise v4-reachable host -- fails fast and the loop falls through
        # to the next address), 8s read per request; the TOTAL per-target budget
        # is scanner.timeout_seconds, enforced inside Scanner.scan via wait_for.
        self._http_client = httpx.AsyncClient(
            headers={"User-Agent": "csreg-scanner/1.0 (registration scanner; +https://github.com/ll-SKY-ll/Matrix-federation-scanner)", "Accept": "application/json"},
            timeout=httpx.Timeout(8.0, connect=3.0),
            follow_redirects=False,
            trust_env=False,
        )
        self.scanner = Scanner(
            float(self.config["scanner.timeout_seconds"]),
            self.log,
            client=self._http_client,
        )

        # policy governance
        self.policy = PolicyManager(
            self.client,
            RoomID(self.config["policy_room"]),
            auto_config_type=self.config["auto_config_event_type"],
            max_writes_per_second=float(self.config["policy.max_writes_per_second"]),
            known_statuses=KNOWN_STATUSES,
            log=self.log,
            domain_statuses=self.db.statuses_for_domain,
        )
        await self.policy.load_rules()
        await self.policy.refresh_auto_config()

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
        for entry in (self.config["sources.textfiles"] or []):
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
        if self.config["sources.postgres.enabled"]:
            try:
                # Construction validates the query is SELECT-only and can raise;
                # connect can fail on a bad DSN. Either disables the source
                # rather than killing the plugin.
                self._pg = PostgresSource(
                    self.config["sources.postgres.dsn"],
                    self.config["sources.postgres.query"],
                    self.log,
                )
                await self._pg.connect()
                self._sources.append(
                    (self._pg, int(self.config["sources.postgres.interval_seconds"]))
                )
            except Exception as e:  # noqa: BLE001 -- don't let a bad DSN/query kill the plugin
                self.log.error("postgres source disabled: %s", e,
                               extra={"csreg_alarm": "postgres_connect_failed"})
                self._pg = None

        # Policy list as a source: re-verify domains already in the shared room.
        # No connect step -- it just reads policy's in-memory fold.
        if self.config["sources.policy_list.enabled"]:
            self._sources.append((
                PolicyListSource(self.policy, self.log),
                int(self.config["sources.policy_list.interval_seconds"]),
            ))

        # metrics server (own address, toggleable)
        self.metrics = None
        if self.config["metrics.enabled"]:
            self.metrics = MetricsServer(
                self.config["metrics.listen_host"],
                int(self.config["metrics.listen_port"]),
                self.config["metrics.path"],
                self.config["metrics.counts_path"],
                self._metrics_snapshot,
                self.log,
                expose_per_server=bool(self.config["metrics.expose_per_server"]),
            )
            await self.metrics.start()

        # background clocks
        for source, interval in self._sources:
            self._tasks.append(asyncio.create_task(self._source_loop(source, interval)))
        if self.scanner is not None:
            self._tasks.append(asyncio.create_task(self._scan_loop()))
            self._tasks.append(asyncio.create_task(self._rescan_loop()))

        self.log.info("csreg started: %d source(s), scanner=%s, metrics=%s",
                      len(self._sources), bool(self.scanner), bool(self.metrics))

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
        inflight = list(getattr(self, "_inflight", ()))
        for t in inflight:
            t.cancel()
        pending = list(getattr(self, "_tasks", [])) + inflight
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if getattr(self, "_pg", None) is not None:
            await self._pg.close()
        if getattr(self, "metrics", None) is not None:
            await self.metrics.stop()
        # Close the scanner's owned resources before the shared client. The
        # scanner does NOT own the injected self._http_client (its aclose() is a
        # no-op for that), but the federation version probe keeps its OWN
        # verify-disabled client internally -- scanner.aclose() is the only thing
        # that closes it, so skipping this leaks that client + its pool on every
        # stop()/config reload.
        if getattr(self, "scanner", None) is not None:
            await self.scanner.aclose()
        # Close the shared httpx client last, after all in-flight scans that
        # borrow it have been cancelled and awaited above.
        if getattr(self, "_http_client", None) is not None:
            await self._http_client.aclose()

    async def on_external_config_update(self) -> None:
        """maubot calls this when the instance config is edited. Nothing here is
        live-reloadable in place (loops capture intervals, _staleness is built at
        start, the metrics socket is already bound), so the robust move is a full
        teardown + rebuild: stop() cancels every loop and in-flight scan, closes
        the pg source and the metrics listener; start() re-reads the YAML and
        rebinds everything. Brief scan interruption + metrics-socket rebind is
        the accepted cost. Guarded so an exception can't leave a half-running
        instance with orphaned loops."""
        self.log.info("config changed; restarting plugin runtime")
        try:
            await self.stop()
        except Exception as e:  # noqa: BLE001
            self.log.warning("error during config-reload stop(): %s", e)
        await self.start()

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

    def _clean(self, raw: list[str]) -> list[str]:
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
            return
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

    @web.post("/ingest")
    async def webhook_ingest(self, req: Request) -> Response:
        """Push ingress. Body: newline/space-separated names, or
        JSON {"servers": [...]}."""
        if not self.config["sources.webhook.enabled"]:
            return Response(status=404)
        secret = self.config["sources.webhook.secret"]
        auth = req.headers.get("Authorization", "")
        # Constant-time compare to avoid leaking the secret via timing. An empty
        # configured secret hard-fails closed (never treat "" as open).
        if not secret or not hmac.compare_digest(auth, f"Bearer {secret}"):
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
        host = self.config["metrics.listen_host"] or "127.0.0.1"
        # A 0.0.0.0/:: listen host isn't a valid *connect* target; loop back.
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = int(self.config["metrics.listen_port"])
        path = self.config["metrics.counts_path"]
        return f"http://{host}:{port}{path}"

    @web.get("/calc/data")
    async def calc_data(self, _req: Request) -> Response:
        """Server-side fetch of the local /counts only. Pass-through to the
        browser so the metrics port need not be reachable from the client and
        no server list is ever pulled (we deliberately do NOT touch /metrics)."""
        if not self.config["metrics.enabled"]:
            return Response(status=503, text='{"error":"metrics disabled"}',
                            content_type="application/json")
        url = self._counts_url()
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url) as resp:
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

    @web.get("/calc")
    async def calc_page(self, _req: Request) -> Response:
        """Self-hosted calculator UI. The page is a static asset shipped in the
        package (csreg_scanner/web/calc.html) -- no external assets (DSGVO): all
        CSS/JS inline, system font stack only. Loaded once and cached in
        memory."""
        return Response(text=_load_calc_html(), content_type="text/html",
                        charset="utf-8")


    # --- scan tick (drains the queue, -----------------------------------------

    async def _scan_loop(self) -> None:
        interval = int(self.config["queue.scan_interval_seconds"])
        limit = int(self.config["queue.scan_batch_limit"])
        # Lease window for a claimed queue row: the scan can't still be alive
        # past the scanner timeout, so +1s of slack is enough for the terminal
        # write to land. A crashed/cancelled scan's row frees itself once this
        # lease expires (see db.pending / db.record_scan).
        lease_seconds = int(float(self.config["scanner.timeout_seconds"])) + 1
        while True:
            try:
                pending = await self.db.pending(limit, lease_seconds)
                for target in pending:
                    self._launch_scan(target, "scan")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("scan tick error: %s", e)
            await asyncio.sleep(interval)

    # --- rescan tick (most-overdue,) ---------------------------------------------

    async def _rescan_loop(self) -> None:
        interval = int(self.config["rescan.interval_seconds"])
        limit = int(self.config["rescan.batch_limit"])
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
                take = min(int(self._rescan_credit), limit)
                if take >= 1:
                    due = await self.db.most_overdue(self._staleness, take)
                    for target in due:
                        self._launch_scan(target, "rescan")
                    # Spend credit only for work actually launched: if fewer were
                    # overdue than authorized, keep the rest so newly-due servers
                    # are picked up promptly rather than forfeiting the budget.
                    self._rescan_credit -= len(due)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.log.warning("rescan tick error: %s", e)
            await asyncio.sleep(interval)

    # --- shared scan unit ----------------------------------------------------

    def _launch_scan(self, scan_target: str, kind: str) -> None:
        """Fire a scan as a tracked background task. The tick does NOT await it:
        each tick launches its batch and returns to its fixed-rate clock, so the
        batch_limit is the per-tick concurrency and the scanner timeout is the
        natural ceiling on simultaneously-running scans. Tracked in _inflight so
        the task can't be GC'd mid-run; the done-callback logs failures and
        unregisters it."""
        task = asyncio.create_task(self._scan_one(scan_target))
        self._inflight.add(task)
        task.add_done_callback(lambda t: self._scan_done(t, kind))

    def _scan_done(self, task: asyncio.Task, kind: str) -> None:
        self._inflight.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self.log.warning(
                "%s task raised: %s", kind, exc,
                extra={"csreg_alarm": f"{kind}_task_error"},
            )

    async def _scan_one(self, scan_target: str) -> None:
        t0 = time.monotonic()
        result, version = await self.scanner.scan(scan_target)
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

        # Per-scan result log. Structured fields are ALWAYS present in extra
        # (null where N/A) for a future JSON log shipper, but our current pipeline
        # forwards only the MESSAGE TEXT, so the human-facing facts are also 
        # embedded in the message as logfmt key=value pairs for key-value extraction. 
        #
        # Level: a reg-status transition -- including the first-ever sighting of
        # a target (previous_status None) -- is INFO so it surfaces in the maubot
        # web log. An unchanged status is DEBUG (the steady-state
        # rescan firehose stays out of INFO). A task-failure is not a transition
        # and stays DEBUG too; it carries the (quoted) error instead of version
        # keys, since the version probe is skipped when the reg-scan fails.
        extra = {
            "csreg_event": "scan_result",
            "scan_target": scan_target,
            "reg_status": result.status,
            "previous_status": record.previous_status,
            "fed_name": version.name,
            "fed_version": version.version,
        }
        # logfmt rendering of the version pair, shared by the change/unchanged
        # lines. A null name/version renders as "-" (kept out of the message as
        # the literal None so it can't collide with a real value).
        ver_kv = (
            f"name={version.name if version.name is not None else '-'} "
            f"version={version.version if version.version is not None else '-'}"
        )
        if not result.ok:
            extra["scan_error"] = result.error
            # Quote the free-text error and neutralize any inner double-quotes so
            # error="..." stays a single well-formed key=value for the extractor.
            err = (result.error or "").replace('"', "'")
            self.log.debug(
                'scan failed for %s: error="%s"', scan_target, err, extra=extra
            )
        elif record.changed:
            self.log.info(
                "reg-status change for %s: %s -> %s %s",
                scan_target, record.previous_status, result.status, ver_kv,
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

    # --- observability ----------------------------------------------------------

    def _rates(self, buckets: dict[str, int]) -> tuple[float, float]:
        # Required rescan rate = sum(N_bucket / T_bucket) servers/sec. Achievable
        # rate is now pure throughput -- batch_limit launched per interval -- and
        # no longer depends on measured scan duration (durations are too dynamic
        # to drive config; they stay as metrics only). required > achievable is
        # the "falling behind on staleness" signal.
        required = self._required_rate(buckets)
        interval = int(self.config["rescan.interval_seconds"])
        batch = int(self.config["rescan.batch_limit"])
        achievable = batch / interval if interval > 0 else 0.0
        return required, achievable

    def _required_rate(self, buckets: dict[str, int]) -> float:
        """Demand in scans/sec to keep every bucket within its staleness T:
        sum(N_bucket / T_bucket). Shared by the capacity alarm and the rescan
        rate-meter so they can never disagree."""
        default_t = self._staleness.get("unknown", 86400)
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

    async def _metrics_snapshot(self) -> dict:
        # Skip the full scanned-table read when per-server series are disabled;
        # nothing else consumes `servers`, and bucket_counts is a cheap GROUP BY.
        if self.config["metrics.expose_per_server"]:
            servers = await self.db.all_statuses()
        else:
            servers = []
        buckets = await self.db.bucket_counts()
        total = sum(buckets.values())
        queue_depth = await self.db.queue_depth()
        total_scans = await self.db.total_scans()
        required, achievable = self._rates(buckets)
        fed_versions = await self.db.fed_version_counts()
        return {
            "servers": servers,
            "buckets": buckets,
            "total": total,
            "total_scans": total_scans,
            "queue_depth": queue_depth,
            "active_rules": self.policy.active_rules(),
            "halted": self.policy.halted,
            "avg_scan": self._avg_scan,
            "required_rate": required,
            "achievable_rate": achievable,
            "fed_versions": fed_versions,
        }