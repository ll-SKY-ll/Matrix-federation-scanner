"""Tests for the SSRF connection-target filter (csreg_scanner/ipfilter.py).

Why this file exists
--------------------
A scanned server controls its own delegation, so it chooses the host:port the
scanner dials. ipfilter.py is the gate that stops that from being a blind SSRF
primitive. The failure that hurts is FAIL-OPEN: the gate saying "yes, connect"
to an address it should have denied. So the tests here are weighted toward the
refusal cases -- proving the gate says NO -- not the happy path.

Coverage picked deliberately (units 1-4 of the walkthrough):
  1. IPRangePolicy.allows      -- the allow/deny decision itself
  2. _parse_address            -- the parser feeding allows (its failure feeds
                                  allows's fail-open None branch)
  3. parse_networks            -- config parsing; a malformed blacklist here can
                                  silently disable the whole filter
  4. FilteringResolver.resolve -- enforcement: filter the address LIST, raise
                                  only when nothing survives

NOT covered here (by choice): build_connector wiring / the fail-loud hasattr
branch (unit 5), and FilteringTCPConnector._resolve_host (same filtering logic
as FilteringResolver, different call site -- tested via the resolver).

These are pure-logic tests: no network, no maubot runtime, no DB. The one async
piece (the resolver) is driven with a hand-written fake inner resolver, so no
real DNS or sockets are touched.
"""

from __future__ import annotations

import ipaddress
import logging

import pytest

# Import the submodule directly (not the package): conftest puts bot/ on
# sys.path, and importing csreg_scanner.ipfilter still runs the package
# __init__, which pulls the plugin stack -- that's expected and matches CI.
from csreg_scanner import ipfilter


# A throwaway logger for the units that warn. We don't assert on log output in
# most tests; where we do (parse_networks warnings) we use caplog.
_LOG = logging.getLogger("test_ipfilter")


def _net(cidr: str):
    """Shorthand: CIDR string -> ip_network, matching how config is parsed."""
    return ipaddress.ip_network(cidr)


# ---------------------------------------------------------------------------
# Unit 1: IPRangePolicy.allows -- the decision. The core fail-open guard.
# ---------------------------------------------------------------------------
#
# Contract (from the source): parse the address; unparseable -> True (nothing to
# decide); in whitelist -> True (whitelist wins outright); otherwise True only
# if NOT in any denied range.


def test_allows_denies_blacklisted_address():
    """THE fail-open guard: a denied address must return False.

    If this ever returns True, the SSRF gate is defeated -- the scanner would be
    allowed to connect to an address the operator blacklisted. This is the
    single most important assertion in the file.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("127.0.0.0/8")])
    assert policy.allows("127.0.0.1") is False


def test_allows_permits_address_outside_blacklist():
    """The necessary complement: an address NOT in any denied range is allowed.

    Without this, a filter that just returned False for everything would pass
    the test above while breaking all legitimate scans. This proves the gate
    isn't stuck closed.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("127.0.0.0/8")])
    assert policy.allows("8.8.8.8") is True


def test_allows_whitelist_beats_blacklist_without_opening_the_rest():
    """Whitelist wins for the carved-out prefix -- AND the rest of the blacklist
    stays intact.

    Split-horizon operators whitelist their own internal prefix to carve it back
    out of the default blacklist. The danger in "get whitelist working" is
    accidentally neutering the blacklist. So this asserts BOTH halves: the
    whitelisted address is allowed, and a *different* address still inside the
    blacklisted range is still denied. The second assert is what makes this a
    fail-open guard rather than a feature demo.
    """
    policy = ipfilter.IPRangePolicy(
        blacklist=[_net("10.0.0.0/8")],
        whitelist=[_net("10.1.2.0/24")],
    )
    assert policy.allows("10.1.2.5") is True    # carved-out prefix allowed
    assert policy.allows("10.9.9.9") is False   # rest of the /8 still denied


def test_allows_non_ip_returns_true_the_deliberate_fail_open():
    """The deliberate fail-OPEN branch: a non-IP target is not our decision.

    _parse_address returns None for anything that isn't an IP (a unix socket
    path, garbage), and allows() treats None as "nothing to filter" -> True.
    This is intended, but it IS a fail-open, so it's pinned down explicitly:
    even with a deny-everything blacklist, a non-IP string is allowed through
    because there's no IP to judge. If this ever changed, it'd change silently.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("0.0.0.0/0")])  # deny all v4
    assert policy.allows("/run/some.sock") is True


def test_allows_ipv6_denied_is_actually_denied():
    """The v6 side of the fail-open guard.

    A v6 literal in a denied range must be denied. This guards against the
    parser mishandling v6 (brackets/scope) and letting a denied v6 slip through
    as an unparseable None -> True. Pairs with the _parse_address tests below.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("::1/128")])
    assert policy.allows("::1") is False
    assert policy.allows("[::1]") is False   # bracketed form, same address


# ---------------------------------------------------------------------------
# Unit 2: _parse_address -- the parser feeding allows().
# ---------------------------------------------------------------------------
#
# Why fail-safe relevant: if this returns None for something that IS a denied
# IP, that None flows into allows() and becomes True -- a fail-open. So the job
# here is to prove the normalization forms the code claims to handle actually
# reduce to a real address, and that only genuine garbage returns None.


def test_parse_address_strips_brackets():
    """Bracketed v6 ([::1]) must parse to the bare address, not None."""
    assert ipfilter._parse_address("[::1]") == ipaddress.ip_address("::1")


def test_parse_address_strips_scope_id():
    """A scope/zone id (fe80::1%eth0) must be stripped and the address parsed.

    getaddrinfo can hand back scoped addresses; if this rejected them as None
    they'd become fail-open in allows(). Assert the scope is dropped and the
    remaining address parses.
    """
    assert ipfilter._parse_address("fe80::1%eth0") == ipaddress.ip_address("fe80::1")


def test_parse_address_plain_ipv4():
    """A plain v4 literal parses (the common case, kept honest)."""
    assert ipfilter._parse_address("127.0.0.1") == ipaddress.ip_address("127.0.0.1")


def test_parse_address_garbage_returns_none():
    """Genuinely non-IP input returns None (e.g. a unix socket path).

    This is the input that legitimately drives allows()'s fail-open branch -- so
    we want it to be None ONLY for real non-addresses, which the tests above
    (that real addresses parse) bracket from the other side.
    """
    assert ipfilter._parse_address("/run/some.sock") is None
    assert ipfilter._parse_address("not-an-ip") is None


# ---------------------------------------------------------------------------
# Unit 3: parse_networks -- config parsing, with a fail-open lurking.
# ---------------------------------------------------------------------------
#
# Per-entry tolerance is intended: a typo'd CIDR is warned + skipped, not fatal.
# The lurking danger: if the *blacklist* config parses to an empty list, the
# policy goes inert (active == False) and the filter turns OFF. So the
# "malformed input -> empty list" behavior is exactly the thing to pin down, and
# the active-goes-False consequence is asserted so the fail-open is visible.


def test_parse_networks_drops_bad_keeps_good():
    """Valid CIDRs are kept; invalid/blank entries are dropped, not fatal."""
    nets = ipfilter.parse_networks(
        ["10.0.0.0/8", "not-a-cidr", "   "], _LOG, field="ip_range_blacklist"
    )
    assert nets == [_net("10.0.0.0/8")]


def test_parse_networks_accepts_host_bits_strict_false():
    """strict=False: a host address with a prefix (10.0.0.5/8) is accepted.

    This is the forgiving reading of operator intent the source documents. Not a
    fail-safe concern, but it's a documented behavior worth locking so a future
    strict=True change doesn't silently start dropping operator entries.
    """
    nets = ipfilter.parse_networks(["10.0.0.5/8"], _LOG, field="x")
    assert nets == [_net("10.0.0.0/8")]


def test_parse_networks_non_list_returns_empty():
    """Non-list config (operator wrote a bare string) -> empty list, no crash."""
    assert ipfilter.parse_networks("10.0.0.0/8", _LOG, field="x") == []


def test_parse_networks_strict_blacklist_non_list_raises():
    """A malformed (non-list) BLACKLIST fails CLOSED: raises IPRangeConfigError.

    This replaces the former FAIL-OPEN behavior. A blacklist that isn't even a
    list is intent-to-restrict the code can't honor; silently returning empty
    would disable the SSRF filter entirely. Strict mode raises so start() aborts
    before the scan loops launch -- no scanning happens until it's fixed. Same
    reasoning as a malformed min_bot_version halting rather than being ignored.
    """
    with pytest.raises(ipfilter.IPRangeConfigError):
        ipfilter.parse_networks("10.0.0.0/8", _LOG, field="blacklist", strict=True)


def test_parse_networks_strict_blacklist_bad_entry_raises():
    """A single invalid CIDR in the BLACKLIST fails closed (strictest posture).

    One typo'd entry means an intended denied range isn't denied -- a silent
    hole in the SSRF filter. Per the chosen posture, that grounds the scanner
    until fixed rather than enforcing a partial blacklist.
    """
    with pytest.raises(ipfilter.IPRangeConfigError):
        ipfilter.parse_networks(
            ["10.0.0.0/8", "not-a-cidr"], _LOG, field="blacklist", strict=True
        )


def test_parse_networks_strict_blacklist_empty_entry_raises():
    """A blank/non-string entry in a strict BLACKLIST also raises."""
    with pytest.raises(ipfilter.IPRangeConfigError):
        ipfilter.parse_networks(
            ["10.0.0.0/8", "  "], _LOG, field="blacklist", strict=True
        )


def test_parse_networks_strict_blacklist_all_valid_ok():
    """A fully-valid strict blacklist parses normally (not stuck-closed)."""
    nets = ipfilter.parse_networks(
        ["10.0.0.0/8", "127.0.0.0/8"], _LOG, field="blacklist", strict=True
    )
    assert nets == [_net("10.0.0.0/8"), _net("127.0.0.0/8")]


def test_parse_networks_strict_empty_list_is_ok():
    """An EMPTY or ABSENT blacklist is NOT malformed -- it means 'don't filter'.

    The distinction that matters: [] / None is a deliberate choice not to
    restrict (fail-open is correct -- nothing was requested), whereas a MALFORMED
    value is a failed attempt TO restrict (fail-closed). So an empty list in
    strict mode must NOT raise; it just yields an inert (but intentionally so)
    policy.
    """
    assert ipfilter.parse_networks([], _LOG, field="blacklist", strict=True) == []
    assert ipfilter.parse_networks(None, _LOG, field="blacklist", strict=True) == []


def test_parse_networks_whitelist_stays_lenient():
    """The WHITELIST is deliberately NOT strict: bad entries are dropped, warned.

    A whitelist only carves exceptions OUT of the blacklist, so dropping a bad
    whitelist entry fails toward MORE filtering (safe). It must stay lenient so
    one whitelist typo can't ground the scanner. (strict defaults to False.)
    """
    nets = ipfilter.parse_networks(
        ["10.1.2.0/24", "not-a-cidr", "  "], _LOG, field="whitelist"
    )
    assert nets == [_net("10.1.2.0/24")]     # bad dropped, good kept, no raise


def test_parse_networks_warns_on_invalid_entry(caplog):
    """The skip is observable: an invalid entry emits a warning.

    A blocked/skipped entry is otherwise invisible; the operator's only signal is
    the log line. Assert the warning fires, since that's the operator's window
    into 'my config entry was ignored'.
    """
    with caplog.at_level(logging.WARNING):
        ipfilter.parse_networks(["nope"], _LOG, field="ip_range_blacklist")
    assert any("ignoring invalid CIDR" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Unit 4: FilteringResolver.resolve -- enforcement.
# ---------------------------------------------------------------------------
#
# The resolver wraps an inner resolver, filters the returned address LIST
# through the policy, and raises BlockedAddressError only when NOTHING survives.
# The dual-stack subtlety: a denied AAAA alongside an allowed A must still leave
# the host reachable over the A -- it filters the list, it doesn't fail on the
# first denied entry.
#
# We drive it with a fake inner resolver (no real DNS/sockets). The resolver's
# constructor takes `inner`, so the fake slots straight in -- this is the
# "fake client" technique: script the return value, test the logic around it.


class _FakeResolver:
    """Stand-in for aiohttp's inner resolver.

    resolve() ignores its args and returns a scripted list of addrinfo-shaped
    dicts, which is all FilteringResolver reads (it only touches info["host"]).
    """

    def __init__(self, infos):
        self._infos = infos

    async def resolve(self, host, port=0, family=0):
        return self._infos

    async def close(self):
        pass


def _addrinfo(host):
    """Minimal addrinfo dict -- only 'host' is consulted by the filter."""
    return {"host": host}


async def test_resolver_drops_denied_keeps_allowed():
    """Dual-stack fall-through: denied address dropped, allowed one survives.

    The inner resolver returns one denied and one allowed address. The filter
    must return ONLY the allowed one -- not raise -- so a dual-stack host with a
    poisoned AAAA is still reachable over its good A. This proves the filter
    trims the list rather than failing on first-denied (fail-closed-too-hard).
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("127.0.0.0/8")])
    inner = _FakeResolver([_addrinfo("127.0.0.1"), _addrinfo("8.8.8.8")])
    resolver = ipfilter.FilteringResolver(policy, _LOG, inner=inner)

    result = await resolver.resolve("dual.example", 8448)

    assert result == [_addrinfo("8.8.8.8")]


async def test_resolver_raises_when_every_address_denied():
    """The refusal case: if NOTHING survives the filter, raise.

    When every resolved address is in a denied range, the resolver must raise
    BlockedAddressError rather than return an empty list (which would hand
    aiohttp an undefined state). This is the enforcement equivalent of allows()
    returning False -- the point where the gate actually stops the connection.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("127.0.0.0/8")])
    inner = _FakeResolver([_addrinfo("127.0.0.1"), _addrinfo("127.0.0.2")])
    resolver = ipfilter.FilteringResolver(policy, _LOG, inner=inner)

    with pytest.raises(ipfilter.BlockedAddressError):
        await resolver.resolve("evil.example", 8448)


async def test_resolver_passes_everything_through_when_all_allowed():
    """No denied entries -> the full list is returned unchanged.

    Keeps the resolver honest that it isn't dropping legitimate addresses. Pairs
    with the raise test: together they show the filter trims exactly the denied
    entries and nothing more.
    """
    policy = ipfilter.IPRangePolicy(blacklist=[_net("127.0.0.0/8")])
    inner = _FakeResolver([_addrinfo("8.8.8.8"), _addrinfo("1.1.1.1")])
    resolver = ipfilter.FilteringResolver(policy, _LOG, inner=inner)

    result = await resolver.resolve("fine.example", 8448)

    assert result == [_addrinfo("8.8.8.8"), _addrinfo("1.1.1.1")]


async def test_resolver_blocked_error_is_an_oserror():
    """BlockedAddressError must subclass OSError -- a load-bearing detail.

    The source raises this so aiohttp's TCPConnector catches it (it catches
    OSError around resolution) and collapses it into the existing no-signal
    path, recording the scan as `unknown` exactly like an unreachable host. If
    it stopped being an OSError, a blocked target would escape those handlers
    and surface as a task error instead. Cheap to assert, easy to regress.
    """
    assert issubclass(ipfilter.BlockedAddressError, OSError)
