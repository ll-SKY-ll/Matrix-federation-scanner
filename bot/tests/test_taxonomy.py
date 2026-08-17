"""Tests for the status taxonomy (csreg_scanner/taxonomy.py).

Low-stakes but cheap: the status<->metric-value mapping is a stable contract
that existing dashboards depend on. These pin the two invariants that a future
edit could quietly break: every metric-value key is a known status, and the
numeric encodings are stable + unique (a dashboard query keyed on value 3 ==
dangerously_open must never start meaning something else).
"""

from __future__ import annotations

from csreg_scanner.taxonomy import KNOWN_STATUSES, STATUS_METRIC_VALUE


def test_every_metric_key_is_a_known_status():
    """No metric encoding may reference a status outside the vocabulary."""
    assert set(STATUS_METRIC_VALUE) <= KNOWN_STATUSES


def test_metric_values_are_unique():
    """Each status maps to a distinct number (no collisions in the gauge)."""
    values = list(STATUS_METRIC_VALUE.values())
    assert len(set(values)) == len(values)


def test_stable_numeric_encodings():
    """The historical value assignments dashboards depend on must not drift.

    0=unknown,1=closed,2=open,3=dangerously_open are load-bearing for existing
    Grafana queries. Pin them so a reorder can't silently remap a dashboard.
    """
    assert STATUS_METRIC_VALUE["unknown"] == 0
    assert STATUS_METRIC_VALUE["closed"] == 1
    assert STATUS_METRIC_VALUE["open"] == 2
    assert STATUS_METRIC_VALUE["dangerously_open"] == 3


def test_core_statuses_present():
    """The statuses the classifier can emit are all in the vocabulary."""
    for s in ("dangerously_open", "open", "oauth", "closed", "unknown"):
        assert s in KNOWN_STATUSES
