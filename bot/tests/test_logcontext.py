"""Tests for csreg_scanner.logcontext -- the per-scan log-record stamping.

Two things are worth pinning down here, and they are the load-bearing ones:

  1. The ScanTargetFilter puts the *current* scan target onto every record, and
     None when there is no scan in flight. Never drops a record.
  2. The binding is TASK-SCOPED. The scanner fans out one asyncio task per
     target and never resets the contextvar, relying on asyncio running each
     task in a COPY of the context. If that isolation ever broke, concurrent
     scans would cross-contaminate each other's log lines (and, worse, a leaked
     target could mislabel an unrelated line). So the concurrency test is the
     point of this file, not an afterthought.

We deliberately do NOT assert on debug MESSAGE text anywhere -- that would couple
the suite to log wording. The one integration test asserts a structural property
(every debug record from a real classify() run carries the bound target), which
survives any rephrasing of the lines themselves.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from csreg_scanner.logcontext import (
    ScanTargetFilter,
    _scan_target,  # private: tested directly
    bind_scan_target,
)


@pytest.fixture(autouse=True)
def _clean_scan_target():
    """Guarantee a clean baseline regardless of test order.

    bind_scan_target never resets (it relies on task-context disposal in
    production), so a hypothetical future SYNC caller could leave a value set in
    the main context. Resetting to None at setup keeps these tests independent.
    """
    _scan_target.set(None)
    yield


def _record() -> logging.LogRecord:
    return logging.LogRecord(
        "test", logging.DEBUG, __file__, 0, "msg", None, None
    )


class _Capture(logging.Handler):
    """Collects the records it is handed, for post-hoc assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


# --- the filter -------------------------------------------------------------


def test_filter_stamps_none_when_unbound():
    rec = _record()
    assert ScanTargetFilter().filter(rec) is True   # never drops
    assert rec.scan_target is None


def test_filter_stamps_bound_value():
    # Bind on the current context (the autouse fixture resets it afterwards).
    bind_scan_target("matrix.example:8448")
    rec = _record()
    ScanTargetFilter().filter(rec)
    assert rec.scan_target == "matrix.example:8448"


def test_filter_always_returns_true_even_when_bound():
    bind_scan_target("h.example")
    assert ScanTargetFilter().filter(_record()) is True


# --- task scoping / isolation (the important part) --------------------------


async def test_binding_survives_await():
    """A value bound before an await is still there after it -- the scanner
    binds once, then awaits the whole probe chain."""
    filt = ScanTargetFilter()

    async def scan() -> str | None:
        bind_scan_target("survives.example")
        await asyncio.sleep(0)          # force a context switch
        rec = _record()
        filt.filter(rec)
        return rec.scan_target

    assert await scan() == "survives.example"


async def test_no_cross_task_leak():
    """Concurrent scans must not see each other's target.

    This is the guarantee the whole design rests on: one task per target, each
    running in its own context copy, no reset needed. If asyncio's per-task
    context copy ever stopped holding, this is the test that would catch it.
    """
    filt = ScanTargetFilter()
    seen: dict[str, str | None] = {}

    async def scan(name: str) -> None:
        bind_scan_target(name)
        # Interleave the tasks at the await so a leak (shared context) would
        # actually manifest rather than each task running start-to-finish.
        await asyncio.sleep(0)
        rec = _record()
        filt.filter(rec)
        seen[name] = rec.scan_target

    names = [f"s{i}.example" for i in range(25)]
    await asyncio.gather(*(scan(n) for n in names))

    assert seen == {n: n for n in names}


async def test_bind_in_child_task_does_not_leak_to_parent():
    """A target bound inside a spawned task is invisible to the parent context
    once that task is done -- so a scan can never taint a later non-scan line
    (lifecycle, governance, PSL) that runs on the parent."""
    async def child() -> None:
        bind_scan_target("child.example")

    await asyncio.create_task(child())

    rec = _record()
    ScanTargetFilter().filter(rec)
    assert rec.scan_target is None


# --- integration: a real classify() run stamps every debug record -----------


async def test_scan_path_debug_records_carry_target():
    """End-to-end wiring: with the filter attached and a target bound, every
    DEBUG record emitted by a real classify() carries that target.

    Uses the same FakeSession the scanner tests use, scripted to the ambiguous
    403 path (which exercises several debug branches and lands on `unknown`).
    Asserts the structural property -- records carry the target -- not any
    message text.
    """
    from conftest import FakeResponse, FakeSession

    from csreg_scanner.regcheck import UNKNOWN, RegistrationChecker

    log = logging.getLogger("test.logcontext.scanpath")
    log.setLevel(logging.DEBUG)
    filt = ScanTargetFilter()
    cap = _Capture()
    log.addFilter(filt)
    log.addHandler(cap)
    try:
        session = FakeSession(
            get_routes=[(
                "/.well-known/matrix/client",
                FakeResponse(
                    status=200,
                    body={"m.homeserver": {"base_url": "https://h.example"}},
                ),
            )],
            post_routes=[(
                "/register",
                FakeResponse(status=403, body={"errcode": "M_UNKNOWN"}),
            )],
        )
        checker = RegistrationChecker(session, log)

        async def scan() -> str:
            bind_scan_target("h.example")
            return await checker.classify("h.example")

        # Run under a task, exactly as _scan_one does, so the binding is
        # task-scoped rather than leaking onto the test's own context.
        status = await asyncio.create_task(scan())
    finally:
        log.removeHandler(cap)
        log.removeFilter(filt)

    assert status == UNKNOWN  # ambiguous 403 must not become `closed`
    debug_records = [r for r in cap.records if r.levelno == logging.DEBUG]
    assert debug_records, "expected classify() to emit at least one debug line"
    assert all(
        getattr(r, "scan_target", None) == "h.example" for r in debug_records
    )
