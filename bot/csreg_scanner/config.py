"""Config proxy. Mirrors base-config.yaml; all operational config lives in YAML
(-- single source of truth, no DB-backed live config)."""

from __future__ import annotations

from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

_LEAVES = [
    "policy_room",
    "auto_config_event_type",
    "scanner.timeout_seconds",
    "queue.scan_interval_seconds",
    "queue.scan_batch_limit",
    "rescan.interval_seconds",
    "rescan.batch_limit",
    "rescan.staleness_seconds",
    "sources.textfiles",
    "sources.postgres.enabled",
    "sources.postgres.dsn",
    "sources.postgres.query",
    "sources.postgres.interval_seconds",
    "sources.policy_list.enabled",
    "sources.policy_list.interval_seconds",
    "sources.webhook.enabled",
    "sources.webhook.secret",
    "policy.max_writes_per_second",
    "metrics.enabled",
    "metrics.expose_per_server",
    "metrics.listen_host",
    "metrics.listen_port",
    "metrics.path",
    "metrics.counts_path",
]


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        for leaf in _LEAVES:
            helper.copy(leaf)