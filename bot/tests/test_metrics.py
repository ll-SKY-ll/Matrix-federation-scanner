"""Tests for metrics label escaping (csreg_scanner/metrics.py).

Only the injection-ish surface is tested: _esc_label. A scan target is an
attacker-influenceable string that ends up inside a Prometheus label value, so
an unescaped quote/backslash/newline could break the exposition format (or, in
the worst reading, inject synthetic series). The rest of metrics.py is text
formatting whose failure is a wrong dashboard, not a wrong ban -- out of scope.
"""

from __future__ import annotations

from csreg_scanner.metrics import _esc_label


def test_esc_label_escapes_quote():
    """A double-quote is escaped so it can't terminate the label value early."""
    assert _esc_label('a"b') == 'a\\"b'


def test_esc_label_escapes_backslash():
    """A backslash is escaped first (so it can't form an accidental escape)."""
    assert _esc_label('a\\b') == 'a\\\\b'


def test_esc_label_escapes_newline():
    """A newline is escaped so it can't break out of the exposition line."""
    assert _esc_label('a\nb') == 'a\\nb'


def test_esc_label_combined():
    """A hostile-looking value with all three is fully neutralised."""
    out = _esc_label('x"\\\n')
    assert '\n' not in out               # no raw newline survives
    assert out == 'x\\"\\\\\\n'
