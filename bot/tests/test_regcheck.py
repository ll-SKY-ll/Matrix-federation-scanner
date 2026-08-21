"""Tests for the registration classifier (csreg_scanner/regcheck.py).

WHY THIS IS THE MOST IMPORTANT FILE TO TEST
-------------------------------------------
The classifier turns a server's registration behavior into a status label
(dangerously_open / open / oauth / closed / unknown). That label flows straight
into policy.decide() -> ban/unban. So a MISCLASSIFICATION is the root of every
wrong ban: all the fail-safe machinery in policy.py and db.py faithfully carries
out whatever the classifier decided. If the classifier is wrong, the machinery
is correctly, dutifully wrong.

The asymmetry that shapes every test here (from the module's own docstring:
"start-from-unknown and promote-only-on-certainty"):

  * Under-classifying (calling an open server closed/unknown) -> we fail to ban
    something we should -> annoying but SAFE (no wrong action).
  * Over-classifying (calling a closed/ambiguous server dangerously_open) -> we
    BAN AN INNOCENT SERVER -> the actual harm.
  * Mislabelling an ambiguous refusal as `closed` -> could UNBAN a still-
    dangerous server -> also harm.

So the tests are weighted toward two "must never" properties:
  1. Never escalate toward dangerous without POSITIVE evidence of a frictionless
     path.
  2. Never emit a definite `closed` from an ambiguous signal (WAF 403, 400,
     unparseable body) -- those must be `unknown`.

Two altitudes:
  * PURE: classify_register_body / _flow_classification -- the actual
    classification rules, tested exhaustively with no network.
  * HTTP-MAPPING: _probe_register status/body -> signal, and classify()'s
    precedence ladder + fail-to-unknown -- tested with a FakeSession.
"""

from __future__ import annotations

import logging

from conftest import FakeResponse, FakeSession

from csreg_scanner.regcheck import (
    CLOSED,
    DANGEROUSLY_OPEN,
    OAUTH,
    OPEN,
    UNKNOWN,
    RegistrationChecker,
    _flow_classification,
    classify_register_body,
)

_LOG = logging.getLogger("test_regcheck")


# ===========================================================================
# PURE LAYER 1: _flow_classification -- one flow's stages -> a verdict.
# ===========================================================================
#
# The single most safety-critical rule: only a flow we can AFFIRM is frictionless
# (empty, or exclusively dummy/terms) may return DANGEROUSLY_OPEN. Anything with
# a verifier is guarded (None); anything with an unrecognised stage is OPEN, not
# dangerous.


def test_flow_empty_stages_is_dangerous():
    """An empty stage list is a genuinely zero-friction path -> dangerous."""
    assert _flow_classification([]) == DANGEROUSLY_OPEN


def test_flow_only_non_verifying_is_dangerous():
    """dummy / terms only = frictionless a bot can walk unattended -> dangerous."""
    assert _flow_classification(["m.login.dummy"]) == DANGEROUSLY_OPEN
    assert _flow_classification(["m.login.dummy", "m.login.terms"]) == DANGEROUSLY_OPEN


def test_flow_with_verifier_is_guarded_NEVER_dangerous():
    """A verifying stage guards the flow -> None (never dangerous).

    THE core escalation guard. If a recaptcha/email/token flow ever classified
    as dangerous, an innocent (properly-gated) server would be banned. Every
    verifier in the allowlist is checked.
    """
    for verifier in (
        "m.login.recaptcha",
        "m.login.email.identity",
        "m.login.msisdn",
        "m.login.registration_token",
        "org.matrix.msc3231.login.registration_token",
    ):
        assert _flow_classification([verifier]) is None, verifier


def test_flow_verifier_plus_dummy_still_guarded():
    """A verifier guards the flow even alongside a dummy stage.

    The presence of friction anywhere in the flow is what matters; a dummy
    alongside recaptcha does not make the flow walkable.
    """
    assert _flow_classification(["m.login.recaptcha", "m.login.dummy"]) is None


def test_flow_unrecognised_stage_is_OPEN_not_dangerous():
    """THE documented bias inversion: an unrecognised stage -> OPEN, not dangerous.

    An unfamiliar stage MIGHT impose friction, so the classifier refuses to
    escalate to dangerous on it. This is the difference between "we can affirm
    this is walkable" and "we don't recognise this" -- and it is exactly the
    conservative choice that prevents over-classification of novel auth flows.
    """
    assert _flow_classification(["m.login.sso"]) == OPEN


def test_flow_dummy_plus_unrecognised_is_OPEN_not_dangerous():
    """A dummy alongside an unrecognised stage is OPEN, not dangerous.

    The unrecognised stage might be friction, so even with a dummy present the
    flow is not affirmed frictionless. Conservative: no escalation.
    """
    assert _flow_classification(["m.login.dummy", "m.login.sso"]) == OPEN


def test_flow_non_list_is_none():
    """A malformed (non-list) stages value is no evidence of anything -> None."""
    assert _flow_classification("not-a-list") is None
    assert _flow_classification(None) is None


# ===========================================================================
# PURE LAYER 2: classify_register_body -- a whole UIA body -> a label.
# ===========================================================================


def test_body_single_dangerous_flow():
    """One frictionless flow makes the whole server dangerous (attacker picks it)."""
    body = {"flows": [{"stages": []}]}
    assert classify_register_body(body) == DANGEROUSLY_OPEN


def test_body_mixed_dangerous_wins_precedence():
    """A guarded flow + a dangerous flow -> dangerous.

    Precedence: an attacker simply picks the frictionless path, so the guarded
    flow is irrelevant. If this ever returned `open`, a genuinely dangerous
    server would be under-classified and NOT banned -- the miss direction, but
    still a miss the operator explicitly wants caught.
    """
    body = {"flows": [
        {"stages": ["m.login.recaptcha"]},
        {"stages": []},
    ]}
    assert classify_register_body(body) == DANGEROUSLY_OPEN


def test_body_all_guarded_is_open_not_closed():
    """An all-guarded 401 body is OPEN, not closed.

    A 401 UIA challenge means registration IS possible (just gated). Calling it
    `closed` would be wrong in the dangerous direction: `closed` can trigger an
    unban. So a gated-but-live server must read as open.
    """
    body = {"flows": [{"stages": ["m.login.email.identity"]}]}
    assert classify_register_body(body) == OPEN


def test_body_unrecognised_flow_is_open():
    """A flow of only unrecognised stages -> open (completable in principle)."""
    body = {"flows": [{"stages": ["m.login.sso"]}]}
    assert classify_register_body(body) == OPEN


def test_body_no_usable_flows_is_none():
    """No flows / empty flows / non-dict body -> None (no signal), never a label.

    None becomes `unknown` upstream, never a definite status. A body we can't
    read must not produce a classification.
    """
    assert classify_register_body({}) is None
    assert classify_register_body({"flows": []}) is None
    assert classify_register_body({"flows": "not-a-list"}) is None
    assert classify_register_body("not-a-dict") is None
    assert classify_register_body(None) is None


def test_body_flows_missing_stages_is_none():
    """Flows that never carry a valid stages list -> no usable signal -> None."""
    assert classify_register_body({"flows": [{"foo": 1}]}) is None


# ===========================================================================
# HTTP-MAPPING: _probe_register status/body -> signal.
# ===========================================================================
#
# These use a FakeSession so we drive the real _probe_register over scripted
# responses. The dangerous cases live here: an ambiguous 403/400 must NOT become
# `closed`.


def _checker(post_routes=None, get_routes=None):
    session = FakeSession(get_routes=get_routes or [], post_routes=post_routes or [])
    return RegistrationChecker(session, _LOG)


async def test_probe_401_dangerous_body_is_dangerous():
    """A 401 with a frictionless flow -> dangerously_open."""
    chk = _checker(post_routes=[(
        "/register",
        FakeResponse(status=401, body={"flows": [{"stages": []}]}),
    )])
    assert await chk._probe_register("https://h.example") == DANGEROUSLY_OPEN


async def test_probe_403_M_FORBIDDEN_is_closed():
    """A 403 that AFFIRMATIVELY says M_FORBIDDEN -> closed.

    This is the ONLY path to `closed` from a probe. Positive control for the
    ambiguous-403 tests below.
    """
    chk = _checker(post_routes=[(
        "/register",
        FakeResponse(status=403, body={"errcode": "M_FORBIDDEN"}),
    )])
    assert await chk._probe_register("https://h.example") == CLOSED


async def test_probe_403_other_errcode_is_NOT_closed():
    """A 403 with a NON-M_FORBIDDEN errcode -> no signal (None), NOT closed.

    A WAF/CDN bot-challenge or an IP allowlist blocking our egress returns 403
    with a different errcode. Mislabelling that `closed` could unban a server
    that registers fine for real users. Must be no-signal -> unknown upstream.
    This is the mirror of db.py's ban-erosion guard, at the classifier.
    """
    chk = _checker(post_routes=[(
        "/register",
        FakeResponse(status=403, body={"errcode": "M_UNKNOWN_TOKEN"}),
    )])
    assert await chk._probe_register("https://h.example") is None


async def test_probe_403_no_json_is_NOT_closed():
    """A 403 with a non-JSON body (WAF HTML page) -> no signal, NOT closed."""
    chk = _checker(post_routes=[(
        "/register",
        FakeResponse(status=403, raw="<html>blocked by WAF</html>"),
    )])
    assert await chk._probe_register("https://h.example") is None


async def test_probe_403_closed_ONLY_for_M_FORBIDDEN():
    """The exact contract: a 403 -> closed IF AND ONLY IF errcode is M_FORBIDDEN.

    Verified against the source: the 403 branch returns CLOSED only when
    `body.get("errcode") == "M_FORBIDDEN"`, and None otherwise. This table drives
    several realistic 403 errcodes through the probe and asserts the boundary:
    the spec's disabled-registration signal (M_FORBIDDEN) is the sole path to
    closed; every other 403 -- rate limits, unknown tokens, generic forbidden,
    WAF errcodes -- is no-signal (-> unknown upstream), because treating an
    ambiguous 403 as closed could unban a still-dangerous server.

    Only M_FORBIDDEN (exact string, case-sensitive) may yield closed. If the
    check ever loosened (e.g. any errcode containing 'FORBIDDEN', or any 403),
    the non-M_FORBIDDEN rows here turn red.
    """
    # (errcode, expected)
    cases = [
        ("M_FORBIDDEN", CLOSED),          # the one and only closed signal
        ("M_LIMIT_EXCEEDED", None),       # rate limited != disabled
        ("M_UNKNOWN_TOKEN", None),        # auth quirk
        ("M_FORBID", None),               # near-miss string, must not match
        ("m_forbidden", None),            # wrong case, must not match
        ("CF_CHALLENGE", None),           # WAF/CDN challenge errcode
        ("", None),                       # empty errcode
    ]
    for errcode, expected in cases:
        chk = _checker(post_routes=[(
            "/register", FakeResponse(status=403, body={"errcode": errcode}),
        )])
        got = await chk._probe_register("https://h.example")
        assert got == expected, f"403 errcode {errcode!r}: expected {expected}, got {got}"

    # And a 403 with NO errcode key at all is likewise not closed.
    chk = _checker(post_routes=[(
        "/register", FakeResponse(status=403, body={"error": "nope"}),
    )])
    assert await chk._probe_register("https://h.example") is None


async def test_probe_400_unrecognized_is_not_closed():
    """A 400 (endpoint not served, common on OAuth servers) -> no signal.

    Not closed: the legacy endpoint being absent is not "registration disabled".
    """
    chk = _checker(post_routes=[(
        "/register",
        FakeResponse(status=400, body={"errcode": "M_UNRECOGNIZED"}),
    )])
    assert await chk._probe_register("https://h.example") is None


async def test_probe_404_5xx_429_are_no_signal():
    """404 / 5xx / 429 all -> no signal (None), never a definite label."""
    for status in (404, 500, 502, 429):
        chk = _checker(post_routes=[("/register", FakeResponse(status=status))])
        assert await chk._probe_register("https://h.example") is None, status


async def test_probe_network_error_is_no_signal():
    """A transport error during the probe -> None (no signal), never a label."""
    import aiohttp
    chk = _checker(post_routes=[(
        "/register", aiohttp.ClientError("connection reset"),
    )])
    assert await chk._probe_register("https://h.example") is None


# ===========================================================================
# classify(): the precedence ladder + fail-to-unknown.
# ===========================================================================
#
# classify wires base-URL resolution + the register probe + oauth detection into
# the precedence ladder: dangerous > oauth > open/closed > unknown. We script the
# well-known (for base URL + oauth) and the register probe.


def _well_known_route(base="https://h.example"):
    """A client well-known that resolves the base URL to `base`, no oauth."""
    return (
        "/.well-known/matrix/client",
        FakeResponse(status=200, body={"m.homeserver": {"base_url": base}}),
    )


async def test_classify_dangerous_wins_over_oauth():
    """A live unguarded legacy flow beats an OAuth announcement.

    The server advertises oauth (m.authentication in well-known) AND serves a
    frictionless 401 register flow. dangerous must win -- an attacker walks the
    live legacy path regardless of what the server announces. If oauth won here,
    a genuinely dangerous server would be labelled oauth and (depending on the
    map) not banned.
    """
    wk = {
        "m.homeserver": {"base_url": "https://h.example"},
        "m.authentication": {"issuer": "https://oidc.example"},
    }
    chk = _checker(
        get_routes=[("/.well-known/matrix/client", FakeResponse(status=200, body=wk))],
        post_routes=[("/register", FakeResponse(status=401, body={"flows": [{"stages": []}]}))],
    )
    assert await chk.classify("h.example") == DANGEROUSLY_OPEN


async def test_classify_oauth_when_no_dangerous_legacy():
    """OAuth announced + legacy endpoint absent (400) -> oauth."""
    wk = {
        "m.homeserver": {"base_url": "https://h.example"},
        "m.authentication": {"issuer": "https://oidc.example"},
    }
    chk = _checker(
        get_routes=[("/.well-known/matrix/client", FakeResponse(status=200, body=wk))],
        post_routes=[("/register", FakeResponse(status=400, body={"errcode": "M_UNRECOGNIZED"}))],
    )
    assert await chk.classify("h.example") == OAUTH


async def test_classify_closed_from_forbidden():
    """A clean M_FORBIDDEN with no oauth -> closed."""
    chk = _checker(
        get_routes=[_well_known_route()],
        post_routes=[("/register", FakeResponse(status=403, body={"errcode": "M_FORBIDDEN"}))],
    )
    assert await chk.classify("h.example") == CLOSED


async def test_classify_open_from_guarded_flow():
    """A gated (guarded) 401 flow with no oauth -> open."""
    chk = _checker(
        get_routes=[_well_known_route()],
        post_routes=[("/register", FakeResponse(status=401, body={"flows": [{"stages": ["m.login.recaptcha"]}]}))],
    )
    assert await chk.classify("h.example") == OPEN


async def test_classify_ambiguous_403_is_unknown_NOT_closed():
    """End-to-end: a WAF-style 403 (no M_FORBIDDEN) classifies UNKNOWN.

    The whole-pipeline version of the probe test: an ambiguous refusal must not
    become `closed` (which could unban), it must be `unknown`. This is the
    single most important classify()-level safety assertion in the unban
    direction.
    """
    chk = _checker(
        get_routes=[_well_known_route()],
        post_routes=[("/register", FakeResponse(status=403, body={"errcode": "M_UNKNOWN"}))],
    )
    assert await chk.classify("h.example") == UNKNOWN


async def test_classify_no_base_url_is_unknown():
    """An unparseable target name -> UNKNOWN (no base URL resolvable)."""
    chk = _checker()
    # A name parse_name rejects -> _base_url returns (None, _) -> UNKNOWN.
    assert await chk.classify("[not-a-valid-literal") == UNKNOWN


async def test_classify_never_raises_returns_unknown():
    """classify never propagates an exception; any surprise -> UNKNOWN.

    Script the register POST to raise a non-aiohttp error (an unexpected bug in
    a collaborator). classify's outer try/except must swallow it and return
    unknown, because a scan that raised would wedge the target rather than
    record a safe no-signal.
    """
    chk = _checker(
        get_routes=[_well_known_route()],
        post_routes=[("/register", RuntimeError("unexpected boom"))],
    )
    assert await chk.classify("h.example") == UNKNOWN


async def test_classify_connection_error_is_unknown_not_a_scan_failure():
    """A CONNECTION failure (refused/DNS/network) classifies UNKNOWN, in-band.

    This is the behavior that determines ok= at the scan() layer: because
    classify() catches network errors internally and returns `unknown`, scan()
    takes its SUCCESS path and reports ok=True, status="unknown". An unreachable
    server is therefore a real recorded observation, NOT a task failure (ok=False
    is reserved for an unexpected exception escaping classify() -- see the note
    in test_db.py). Every probe here raises aiohttp.ClientError (what a refused
    connection surfaces as); the result must still be a clean UNKNOWN, never a
    raise.
    """
    import aiohttp
    conn_refused = aiohttp.ClientError("Connection refused")
    chk = _checker(
        get_routes=[
            ("/.well-known/matrix/client", conn_refused),
            ("/auth_metadata", conn_refused),
        ],
        post_routes=[("/register", conn_refused)],
    )
    assert await chk.classify("unreachable.example") == UNKNOWN
