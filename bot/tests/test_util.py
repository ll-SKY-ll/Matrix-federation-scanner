"""Tests for server-name parsing helpers (csreg_scanner/util.py).

These are pure and underpin the whole suite: validate_server_name gates what
reaches the scan queue (sources.py, policy.py) and is_ip_literal decides whether
policy writes a rule at all. util.py's docstring documents TWO past fail-opens
in OPPOSITE directions, and both are pinned here:

  * 999.999.999.999 must NOT be an IP literal (octets > 255 -> it's a DNS name).
    Accepting it as a literal silently SUPPRESSED its policy write == failed open
    toward "not banned".
  * [::ffff:1.2.3.4] (dotted IPv6) MUST be a literal. Rejecting it made policy
    write a rule even with write_policies_for_ip_literals false.
"""

from __future__ import annotations

from csreg_scanner.util import is_ip_literal, strip_port, validate_server_name

# --- is_ip_literal: the two documented past fail-opens --------------------


def test_ip_literal_rejects_out_of_range_v4_octets():
    """999.999.999.999 is NOT a literal: octets > 255 make it a DNS name.

    The fail-open this guards: accepting it as a literal suppressed its policy
    write (IP-literal writes default off), so a ban-worthy host was silently
    never banned.
    """
    assert is_ip_literal("999.999.999.999") is False


def test_ip_literal_accepts_dotted_ipv6():
    """[::ffff:1.2.3.4] IS a literal ('.' is a valid IPv6char).

    The opposite fail-open: rejecting it made policy write a rule for it even
    with IP-literal writes disabled.
    """
    assert is_ip_literal("[::ffff:1.2.3.4]") is True


def test_ip_literal_basic_cases():
    assert is_ip_literal("1.2.3.4") is True
    assert is_ip_literal("[::1]") is True
    assert is_ip_literal("1.2.3.4:8448") is True
    assert is_ip_literal("matrix.org") is False
    assert is_ip_literal("matrix.org:8448") is False


# --- strip_port: bracket-aware ---------------------------------------------


def test_strip_port_bracket_aware():
    assert strip_port("matrix.org:8448") == "matrix.org"
    assert strip_port("matrix.org") == "matrix.org"
    assert strip_port("[::1]:8448") == "[::1]"      # keeps the brackets
    assert strip_port("[::1]") == "[::1]"


def test_strip_port_malformed_bracket_untouched():
    """A malformed bracketed name is left untouched rather than guessed at."""
    assert strip_port("[::1") == "[::1"


# --- validate_server_name ---------------------------------------------------


def test_validate_accepts_valid_names():
    assert validate_server_name("matrix.org")
    assert validate_server_name("matrix.org:8448")
    assert validate_server_name("1.2.3.4")
    assert validate_server_name("[::1]")
    assert validate_server_name("[2001:db8::1]:8448")


def test_validate_rejects_scope_id():
    """A scope/zone id ('%eth0') is not a valid Matrix server name.

    ipaddress.IPv6Address accepts it, but '%' is not an IPv6char, so the charset
    check must reject it first. This is the guard the sources/policy cleaning
    leans on.
    """
    assert validate_server_name("[fe80::1%eth0]") is False
    assert validate_server_name("fe80::1%eth0") is False


def test_validate_rejects_bare_ipv6_and_junk():
    assert validate_server_name("2001:db8::1") is False   # bare v6, unbracketed
    assert validate_server_name("") is False
    assert validate_server_name("has spaces.com") is False
    assert validate_server_name("x" * 260) is False        # over-length


def test_validate_rejects_bad_port():
    assert validate_server_name("matrix.org:0") is False
    assert validate_server_name("matrix.org:99999") is False
    assert validate_server_name("matrix.org:abc") is False
