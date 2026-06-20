"""Registration-status taxonomy and metric encoding.

Status vocabulary and the Prometheus gauge encoding for the in-process
registration checker (see regcheck.py). The checker emits a subset of
KNOWN_STATUSES: dangerously_open, open, oauth, closed, unknown. oauth_open is
retained as a reserved, never-emitted value for forward-compat (and so existing
metric rows / dashboard queries that reference value 5 never break).
"""

from __future__ import annotations

# --- Internal status vocabulary -----------------------------------------------
# The statuses the checker may record. A server that cannot be contacted is NOT
# a distinct state: classification maps it to "unknown" (a successful, recorded
# observation), so there is no `unreachable` bucket. oauth_open is reserved and
# currently never emitted (we cannot determine OAuth signup policy reliably).
KNOWN_STATUSES: frozenset[str] = frozenset(
    {
        "dangerously_open",
        "open",
        "oauth_open",
        "oauth",
        "unknown",
        "closed",
    }
)

# --- Prometheus gauge encoding ------------------------------------------------
# Keeps the numeric values already used elsewhere (0=unknown,1=closed,2=open,
# 3=dangerously_open) stable so existing dashboards/queries don't break, and
# extends with the oauth buckets. This dict is the single source of truth; the
# /metrics HELP line is generated from it so the two cannot drift.
STATUS_METRIC_VALUE: dict[str, int] = {
    "unknown": 0,
    "closed": 1,
    "open": 2,
    "dangerously_open": 3,
    "oauth": 4,
    "oauth_open": 5,
}


def metric_help_mapping() -> str:
    """Human description of the gauge encoding, generated from the dict."""
    pairs = sorted({v: k for k, v in STATUS_METRIC_VALUE.items()}.items())
    return ", ".join(f"{val}={name}" for val, name in pairs)