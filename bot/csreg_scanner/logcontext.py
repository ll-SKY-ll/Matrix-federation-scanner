"""Per-scan logging context.

Stamps the server name currently being scanned onto every log record emitted
during that scan, so a line from deep in the call stack (resolver, fedversion,
supportinfo, ...) carries the target without every call site having to pass it
explicitly.

Mechanics: the target rides in a ContextVar for the duration of one scan, and a
logging.Filter copies it onto each LogRecord as ``record.scan_target``. Each scan
runs in its own asyncio task, and ``asyncio`` runs a task in a COPY of the
context that was current when the task was created (and again when ``wait_for``
wraps a coroutine in an inner task), so a value ``set`` inside one scan is
visible to everything that scan awaits and invisible to every other concurrent
scan. No reset is needed: the task's context copy is discarded when the task
completes and is never shared with the parent.

Where the value shows up:
  * On the LogRecord, therefore in maubot's JSON-serialized log records -- the
    management log websocket ships the whole record, not just the message text,
    so ``scan_target`` travels to the web viewer / any JSON sink as a field.
  * NOT in the text formatters. Those are shared with maubot-core records that
    never enter a scan context; a ``%(scan_target)s`` token in a shared format
    string would raise KeyError on any core line. Human-facing lines that need
    the target visible in the MESSAGE keep interpolating it there (the viewer's
    inline list shows the message, not record attributes).
"""

from __future__ import annotations

import contextvars
import logging

# None outside any scan -- lifecycle, governance, PSL-refresh, and source lines
# all log with scan_target unset, which is correct: they are not about one
# server. The filter renders that as ``None`` on the record.
_scan_target: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "csreg_scan_target", default=None
)


class ScanTargetFilter(logging.Filter):
    """Annotate every record with the current scan target (or None).

    Attached once to the plugin's logger. Returns True unconditionally -- it
    only adds ``record.scan_target``, it never drops a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_target = _scan_target.get()
        return True


def bind_scan_target(scan_target: str) -> None:
    """Bind ``scan_target`` for the current context.

    Call once at the top of the per-target scan coroutine. Because that
    coroutine runs as its own task, the binding is scoped
    to that scan and needs no explicit reset; concurrent scans never see each
    other's target.
    """
    _scan_target.set(scan_target)
