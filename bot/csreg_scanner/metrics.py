"""Standalone Prometheus metrics endpoint + read-only counts endpoint.

Served on its own configurable host:port (NOT maubot's webapp) so operators can
point Prometheus at a dedicated address and toggle it independently. Exposition
text is hand-rendered -- no prometheus_client dependency, exact control over the
syntax, and one fewer dep.
"""

from __future__ import annotations

import json
import logging
from typing import Awaitable, Callable

from aiohttp import web

from .taxonomy import STATUS_METRIC_VALUE, metric_help_mapping

# A snapshot the bot hands the server on each scrape.
MetricsSnapshot = dict


def _esc_label(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricsServer:
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        counts_path: str,
        snapshot_fn: Callable[[], Awaitable[MetricsSnapshot]],
        log: logging.Logger,
        expose_per_server: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.counts_path = counts_path
        self.snapshot_fn = snapshot_fn
        self.log = log
        self.expose_per_server = expose_per_server
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get(self.path, self._handle_metrics)
        app.router.add_get(self.counts_path, self._handle_counts)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        self.log.info(
            "metrics server listening on http://%s:%d%s", self.host, self.port, self.path
        )

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # --- handlers ------------------------------------------------------------

    async def _handle_metrics(self, _req: web.Request) -> web.Response:
        snap = await self.snapshot_fn()
        body = self._render(snap)
        return web.Response(
            text=body, content_type="text/plain", charset="utf-8"
        )

    async def _handle_counts(self, _req: web.Request) -> web.Response:
        """Read-only per-bucket counts for the stateless config calculator. 
        Discipline: this endpoint serves ONLY counts + scalar capacity
        signals -- never the server list or config. The calculator sizes
        rescan.interval_seconds / batch_limit purely from counts + staleness
        targets, so it needs no scan-duration input (durations are metrics-only
        and live on /metrics, which carries the server list and is not scraped
        here). achievable_rate is the current configured throughput
        (batch_limit / interval)."""
        snap = await self.snapshot_fn()
        payload = {
            "total": snap["total"],
            "buckets": snap["buckets"],
            "queue_depth": snap["queue_depth"],
            "required_rate": round(snap["required_rate"], 6),
            "achievable_rate": round(snap["achievable_rate"], 6),
        }
        return web.json_response(payload, dumps=lambda o: json.dumps(o, sort_keys=True))

    # --- rendering -----------------------------------------------------------

    def _render(self, snap: MetricsSnapshot) -> str:
        out: list[str] = []

        # Per-server registration status + time-in-state. Privacy/cardinality
        # gate: the server label set is effectively the full scan-target list,
        # so these two series are only emitted when expose_per_server is on. The
        # per-bucket counts below are always exposed (no server identities).
        if self.expose_per_server:
            out.append(
                "# HELP matrix_server_registration_status Current registration "
                f"state of Matrix homeservers ({metric_help_mapping()})"
            )
            out.append("# TYPE matrix_server_registration_status gauge")
            for domain, status, _since in snap["servers"]:
                value = STATUS_METRIC_VALUE.get(status, 0)
                out.append(
                    f'matrix_server_registration_status{{server="{_esc_label(domain)}"}} {value}'
                )

            # Per-server time-in-current-state. Unix epoch seconds of the last
            # reg_status transition; subtract from `time()` in PromQL for an age.
            out.append(
                "# HELP csreg_server_state_since_seconds Unix time (s) when this "
                "server's registration status last changed"
            )
            out.append("# TYPE csreg_server_state_since_seconds gauge")
            for domain, _status, since in snap["servers"]:
                if since is None:
                    continue
                out.append(
                    f'csreg_server_state_since_seconds{{server="{_esc_label(domain)}"}} {int(since)}'
                )

        # Overall total.
        out.append(
            "# HELP matrix_server_scanned_total Total number of scanned homeservers"
        )
        out.append("# TYPE matrix_server_scanned_total gauge")
        out.append(f"matrix_server_scanned_total {snap['total']}")

        # Cumulative scan executions (incl. rescans). A real monotonic counter:
        # rate()/increase() give scans-per-interval in Grafana. Survives restarts
        # (derived from persisted scan_count), so no reset spikes in normal ops.
        out.append(
            "# HELP csreg_scans_total Cumulative scan executions including rescans"
        )
        out.append("# TYPE csreg_scans_total counter")
        out.append(f"csreg_scans_total {snap['total_scans']}")

        # The same total split by kind, so the two scan systems can be graphed
        # (and capacity-compared) independently. The aggregate above mixes both
        # paths, so rate(csreg_scans_total) can legitimately exceed
        # csreg_rescan_achievable_scans_per_second whenever the queue path is
        # also scanning -- which reads like a violated capacity limit but isn't.
        # Compare rate(csreg_scans_by_type_total{kind="rescan"}) against the
        # rescan achievable/required gauges instead; kind="initial" is the
        # queue-drain (first-ever scan of a target). The kinds are derived from
        # persisted ground truth (first-vs-subsequent scan, see db.scan_totals),
        # are monotonic across restarts, and sum to csreg_scans_total.
        out.append(
            "# HELP csreg_scans_by_type_total Cumulative scan executions by kind "
            "(initial = first-ever scan via the queue, rescan = every "
            "subsequent scan; kinds sum to csreg_scans_total)"
        )
        out.append("# TYPE csreg_scans_by_type_total counter")
        out.append(f'csreg_scans_by_type_total{{kind="initial"}} {snap["initial_scans"]}')
        out.append(f'csreg_scans_by_type_total{{kind="rescan"}} {snap["rescans"]}')

        # Per-bucket counts.
        out.append(
            "# HELP matrix_server_registration_bucket_count Scanned servers per "
            "registration status"
        )
        out.append("# TYPE matrix_server_registration_bucket_count gauge")
        for status, count in sorted(snap["buckets"].items()):
            out.append(
                f'matrix_server_registration_bucket_count{{status="{_esc_label(status)}"}} {count}'
            )

        # Federation software (name, version) distribution. A pre-aggregated
        # GROUP BY count
        out.append(
            "# HELP matrix_server_federation_version_count Scanned servers per "
            "advertised federation (name, version)"
        )
        out.append("# TYPE matrix_server_federation_version_count gauge")
        for name, version, count, _n_reachable in sorted(snap["fed_versions"]):
            out.append(
                "matrix_server_federation_version_count"
                f'{{name="{_esc_label(name)}",version="{_esc_label(version)}"}} {count}'
            )

        # The same distribution restricted to targets whose registration status
        # is not unknown. This is the denominator to use for "% of servers
        # running X": the plain count above includes the unknown pile
        # (unreachable hosts, WAF-blocked /register, ambiguous bodies), so every
        # share computed against it is deflated by an amount that tracks ingress
        # quality rather than anything about the population. Not a restatement of
        # the series above -- a target can advertise a good fed_name while its
        # registration status is unknown.
        out.append(
            "# HELP matrix_server_federation_version_reachable_count Scanned "
            "servers per advertised federation (name, version), excluding those "
            "whose registration status is unknown"
        )
        out.append("# TYPE matrix_server_federation_version_reachable_count gauge")
        for name, version, _count, n_reachable in sorted(snap["fed_versions"]):
            out.append(
                "matrix_server_federation_version_reachable_count"
                f'{{name="{_esc_label(name)}",version="{_esc_label(version)}"}} '
                f"{n_reachable}"
            )

        # Support-document coverage: how many servers we hold a
        # /.well-known/matrix/support document for. Both read 0 while
        # scanner.fetch_support is off.
        #
        # GRANULARITY: these count DOMAINS, not scan targets. The well-known
        # lives on the origin host, so matrix.org and matrix.org:8448 are two
        # rows in `scanned` but share one support document -- support_info is
        # keyed on the portless domain accordingly. Do NOT divide these by
        # matrix_server_scanned_total; the units differ and the ratio is
        # meaningless. The reachable variant counts a domain when at least one
        # target under it is classified.
        _gauge(out, "matrix_server_support_info_count",
               "Domains for which a /.well-known/matrix/support document is "
               "stored (domain-granular: NOT comparable to "
               "matrix_server_scanned_total, which counts scan targets)",
               snap["support_total"])
        _gauge(out, "matrix_server_support_info_reachable_count",
               "Domains for which a /.well-known/matrix/support document is "
               "stored AND at least one scan target under that domain has a "
               "registration status other than unknown (domain-granular)",
               snap["support_reachable"])

        # Operational gauges.
        _gauge(out, "csreg_scan_queue_depth", "Pending domains in the scan queue",
               snap["queue_depth"])
        # Admission-control visibility: inflight pinned at the ceiling is the
        # "launches are being deferred" signal (paired with the
        # scan_admission_deferred log alarm) -- saturation is a designed state,
        # but never a silent one.
        _gauge(out, "csreg_scans_inflight", "Scan tasks currently in flight",
               snap["inflight"])
        _gauge(out, "csreg_scans_inflight_ceiling",
               "In-flight admission ceiling (queue + rescan batch limits)",
               snap["inflight_ceiling"])
        _gauge(out, "csreg_policy_rules_active", "Active policy rules in local fold",
               snap["active_rules"])
        _gauge(out, "csreg_halted", "1 if policy writes are halted (fail-closed)",
               1 if snap["halted"] else 0)
        _gauge(out, "csreg_scan_duration_seconds_avg",
               "EWMA of single-server scan duration", round(snap["avg_scan"], 4))
        # The 'am I digging my own grave' signal.
        _gauge(out, "csreg_rescan_required_scans_per_second",
               "Required rescan rate = sum(N_bucket / T_bucket)",
               round(snap["required_rate"], 6))
        _gauge(out, "csreg_rescan_achievable_scans_per_second",
               "Configured rescan throughput = rescan.batch_limit / interval",
               round(snap["achievable_rate"], 6))
        # Queue-path (initial scan) nominal drain rate. There is no "required"
        # counterpart here -- ingress demand is bursty, not a steady-state rate
        # -- so this is a reference line, not half of a saturation predicate.
        # Read it two ways: csreg_scan_queue_depth / this = drain ETA for an
        # import; and actual rate(csreg_scans_by_type_total{kind="initial"})
        # sitting below this while queue_depth > 0 = the queue path is being
        # squeezed (shared admission ceiling; see scan_admission_deferred).
        _gauge(out, "csreg_initial_achievable_scans_per_second",
               "Configured queue-drain throughput = queue.scan_batch_limit / "
               "queue.scan_interval_seconds (nominal; shared admission ceiling "
               "applies)",
               round(snap["initial_achievable_rate"], 6))

        # --- config-as-metric -------------------------------------------------
        # Operator settings exposed as gauges: flat lines between config
        # reloads, here so dashboards can draw threshold/reference lines and
        # alerts can compare against settings without hardcoding a copy that
        # silently drifts from the real config. Consistency checks these
        # enable: bucket_size / staleness summed over buckets reconciles with
        # csreg_rescan_required_scans_per_second, and
        # sum(csreg_scan_batch_limit) == csreg_scans_inflight_ceiling.
        # Staleness values are the VALIDATED map the rescan loop actually uses
        # (unknown statuses in raw config are dropped at startup), and the
        # status label matches matrix_server_registration_status for PromQL
        # joins. Queue label values match the by-type counter: initial = the
        # new-scan queue drain, rescan = the staleness-driven loop.
        stale = snap["staleness"]
        if stale:
            out.append(
                "# HELP csreg_rescan_staleness_seconds Configured per-status max "
                "staleness T; a bucket's rescan demand is bucket_size / T"
            )
            out.append("# TYPE csreg_rescan_staleness_seconds gauge")
            for status in sorted(stale):
                out.append(
                    f'csreg_rescan_staleness_seconds{{status="{status}"}} '
                    f"{int(stale[status])}"
                )
        loops = snap["loop_config"]
        out.append(
            "# HELP csreg_scan_interval_seconds Configured tick interval per "
            "scan loop"
        )
        out.append("# TYPE csreg_scan_interval_seconds gauge")
        for q in ("initial", "rescan"):
            out.append(
                f'csreg_scan_interval_seconds{{queue="{q}"}} '
                f"{int(loops[q]['interval'])}"
            )
        out.append(
            "# HELP csreg_scan_batch_limit Configured max launches per tick per "
            "scan loop (their sum is the in-flight admission ceiling)"
        )
        out.append("# TYPE csreg_scan_batch_limit gauge")
        for q in ("initial", "rescan"):
            out.append(
                f'csreg_scan_batch_limit{{queue="{q}"}} '
                f"{int(loops[q]['batch_limit'])}"
            )
        _gauge(out, "csreg_scan_timeout_seconds",
               "Configured total per-target scan budget "
               "(scanner.timeout_seconds); interprets the in-flight gauge: a "
               "scan may legally hold a slot this long",
               round(snap["scan_timeout"], 3))

        return "\n".join(out) + "\n"


def _gauge(out: list[str], name: str, help_text: str, value) -> None:
    out.append(f"# HELP {name} {help_text}")
    out.append(f"# TYPE {name} gauge")
    out.append(f"{name} {value}")