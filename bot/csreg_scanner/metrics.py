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
        for name, version, count in sorted(snap["fed_versions"]):
            out.append(
                "matrix_server_federation_version_count"
                f'{{name="{_esc_label(name)}",version="{_esc_label(version)}"}} {count}'
            )

        # Operational gauges.
        _gauge(out, "csreg_scan_queue_depth", "Pending domains in the scan queue",
               snap["queue_depth"])
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

        return "\n".join(out) + "\n"


def _gauge(out: list[str], name: str, help_text: str, value) -> None:
    out.append(f"# HELP {name} {help_text}")
    out.append(f"# TYPE {name} gauge")
    out.append(f"{name} {value}")