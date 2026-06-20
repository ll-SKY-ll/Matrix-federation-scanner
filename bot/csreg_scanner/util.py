"""helpers to parse server names and strip ports for ACL's"""

from __future__ import annotations

import ipaddress
import re


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


# IP-literal detection 
_IP_LITERAL_V4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$")
_IP_LITERAL_V6 = re.compile(r"^\[[0-9a-fA-F:]+\](?::[0-9]+)?$")


def is_ip_literal(host: str) -> bool:
    """
    True if `host` is a Matrix IP-literal server-name (v4 or bracketed v6),
    with or without a port. 
    """
    host = host.strip()
    return bool(_IP_LITERAL_V4.match(host) or _IP_LITERAL_V6.match(host))


# ---------------------------------------------------------------------------
# Matrix server name validation
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")


def _valid_port(port: str) -> bool:
    return bool(_PORT_RE.match(port)) and 1 <= int(port) <= 65535


def _valid_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def _valid_ipv6_literal(host: str) -> bool:
    if not (host.startswith("[") and host.endswith("]")):
        return False
    try:
        return isinstance(ipaddress.ip_address(host[1:-1]), ipaddress.IPv6Address)
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
