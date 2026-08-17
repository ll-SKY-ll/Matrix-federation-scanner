"""helpers to parse server names and strip ports for ACL's"""

from __future__ import annotations

import ipaddress
import re
import time


def now() -> int:
    """Current time as whole epoch seconds.

    Lives here rather than in db.py so the policy layer can share one definition
    of "now" without importing the DB module.
    """
    return int(time.time())


def strip_port(server_name: str) -> str:
    """Return the portless entity, bracket-aware for IPv6 literals.

        matrix.org:8448  -> matrix.org
        matrix.org       -> matrix.org
        [::1]:8448       -> [::1]
        [::1]            -> [::1]

    The policy rule is keyed on the bare hostname; the IPv6 brackets are part of
    the Matrix server-name representation and are kept.
    """
    s = server_name.strip()
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            return s  # malformed; leave untouched rather than guess
        return s[: end + 1]
    if ":" in s:
        return s.rsplit(":", 1)[0]
    return s


# IP-literal detection, per the spec grammar (appendices, "Server Name"):
#
#   hostname    = IPv4address / "[" IPv6address "]" / dns-name
#   IPv4address = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT   (octets 0..255)
#   IPv6address = 2*45IPv6char
#   IPv6char    = DIGIT / %x41-46 / %x61-66 / ":" / "."
#
# Two things the earlier regex-only version got wrong, in OPPOSITE directions:
#
#   * "." IS in the IPv6char set, so [::ffff:1.2.3.4] is a valid IPv6 literal.
#     Rejecting it meant policy wrote a rule for it even with
#     write_policies_for_ip_literals false (and then ran it through the PSL,
#     tripping psl_unknown_tld).
#   * an IPv4 literal's octets must be 0..255, so 999.999.999.999 is NOT a
#     literal -- it satisfies dns-name (dns-char is DIGIT / ALPHA / "-" / ".")
#     and is therefore a plain DNS name. Accepting it as a literal silently
#     SUPPRESSED its policy write, i.e. failed open toward "not banned".
#
# Both edges are decided here now, so this predicate agrees with
# resolver.parse_name on what is and is not a literal.
_IP_LITERAL_V4 = re.compile(
    r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(?::[0-9]{1,5})?$"
)
_IP_LITERAL_V6 = re.compile(r"^\[([0-9A-Fa-f:.]{2,45})\](?::[0-9]{1,5})?$")


def is_ip_literal(host: str) -> bool:
    """
    True if `host` is a Matrix IP-literal server-name (v4 or bracketed v6),
    with or without a port.
    """
    host = host.strip()
    m4 = _IP_LITERAL_V4.match(host)
    if m4:
        return all(0 <= int(octet) <= 255 for octet in m4.groups())
    m6 = _IP_LITERAL_V6.match(host)
    if m6:
        # Charset+length already gate the grammar (which forbids a scope id);
        # the parser is what decides whether the remainder is a real address.
        try:
            ipaddress.IPv6Address(m6.group(1))
            return True
        except ValueError:
            return False
    return False


# ---------------------------------------------------------------------------
# Matrix server name validation
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_IPV6_CHARS_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")


def _valid_port(port: str) -> bool:
    return bool(_PORT_RE.match(port)) and 1 <= int(port) <= 65535


def _valid_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def _valid_ipv6_literal(host: str) -> bool:
    """Bracketed IPv6 literal per the grammar (2*45 of DIGIT/A-F/a-f/":"/".").

    The charset check runs FIRST and is load-bearing: ipaddress.IPv6Address
    accepts a scope/zone id ("fe80::1%eth0"), but "%" is not an IPv6char, so
    such a name is not a valid Matrix server name and must not validate.
    """
    if not (host.startswith("[") and host.endswith("]")):
        return False
    inner = host[1:-1]
    if not _IPV6_CHARS_RE.match(inner):
        return False
    try:
        ipaddress.IPv6Address(inner)
        return True
    except ValueError:
        return False


def _valid_dns_name(host: str) -> bool:
    if not (1 <= len(host) <= 255):
        return False
    labels = host.split(".")
    return all(label and _DNS_LABEL_RE.match(label) for label in labels)


def validate_server_name(name: str) -> bool:
    """Validate a Matrix server name per the spec grammar."""
    name = name.strip()
    if not name or len(name) > 230:
        return False

    if name.startswith("["):
        close = name.find("]")
        if close == -1:
            return False
        bracket = name[: close + 1]
        rest = name[close + 1:]
        if rest:
            if not rest.startswith(":") or not _valid_port(rest[1:]):
                return False
        return _valid_ipv6_literal(bracket)

    host = name
    if name.count(":") == 1:
        host, port = name.split(":", 1)
        if not _valid_port(port):
            return False
    elif ":" in name:
        # multiple colons without brackets => bare IPv6, not valid as a name
        return False

    return _valid_ipv4(host) or _valid_dns_name(host)
