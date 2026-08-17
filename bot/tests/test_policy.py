"""Tests for the policy governance + write layer (csreg_scanner/policy.py).

The design philosophy this whole file tests, from policy.py's own docstring:

    "Universal floor: anything not positively understood as `ban` or `unban`
     resolves to hold / no-write. The worst a malformed auto_config can do
     (within a known schema) is make the bot NOT act -- never take a wrong
     action."

So nearly every test asks one question in a different costume: when something is
wrong/absent/ambiguous, does the bot fail toward INACTION rather than toward a
wrong write? The tests are organized by theme:

  A. halt gate & OR-logic            -- the master fail-safe
  B. schema gate                     -- fail-closed version bounds
  C. parse_bot_version + version floor
  D. PSL floor (reevaluate_psl_floor)
  E. decide + reconcile guards       -- where a decision becomes a WRITE
  F. glob + eTLD+1 counting
  G. stale cleanup guards
  H. 429 retry-after parsing
  I. load_rules fold-preservation
  W. SCHEMA-WINDOW enforcement       -- keys act only in their version window

Fakes (FakeClient, FakePSL, FakeHolder, make_policy) live in conftest.py. The
FakeClient RECORDS send_state_event into `.writes`, so "did the bot write?" is
just "is client.writes non-empty?" -- the fail-safe question made concrete.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from conftest import FakeClient, FakePSL, FakeHolder, make_policy
from csreg_scanner import policy as pol
from csreg_scanner.policy import parse_bot_version, key_active


DANGEROUS = "dangerously_open"
CLOSED = "closed"
UNKNOWN = "unknown"


def _v1(**extra):
    """A minimal VALID v1 auto_config dict: schema + a recommendation.

    recommendation is load-bearing (hashed into every state key) and must be a
    non-empty string or the bot halts, so the minimal valid config carries it.
    """
    d = {"schema_version": 1, "recommendation": "m.ban"}
    d.update(extra)
    return d


def _v2(**extra):
    d = {"schema_version": 2, "recommendation": "m.ban"}
    d.update(extra)
    return d


# ===========================================================================
# THEME A -- the halt gate. The master fail-safe.
# ===========================================================================


def test_starts_halted_before_any_config():
    """A fresh manager is halted: config not read, rules not loaded.

    The safe default. Before anything is validated, no write may happen.
    """
    pm, _ = make_policy()
    assert pm.halted is True


def test_halted_is_true_if_any_single_source_engaged():
    """halted is the OR of three independent sources; ANY one holds it True.

    Set each source in isolation (clearing the others) and assert halted stays
    True. This is the property the three-flag split exists to guarantee.
    """
    pm, _ = make_policy()

    # Only the config source engaged.
    pm._config_halted = True
    pm._rules_loaded = True
    pm._psl_halt_reason = ""
    assert pm.halted is True

    # Only the rules-not-loaded source engaged.
    pm._config_halted = False
    pm._rules_loaded = False
    pm._psl_halt_reason = ""
    assert pm.halted is True

    # Only the PSL source engaged.
    pm._config_halted = False
    pm._rules_loaded = True
    pm._psl_halt_reason = "psl too old"
    assert pm.halted is True


def test_clearing_one_halt_source_does_not_clear_the_others():
    """The documented past fail-open: clearing config-halt must NOT un-halt a
    rule-fold failure.

    policy.py records that a single `halted` flag once let a successful
    _apply_auto_config clear a rule-fold failure too -- enabling writes against
    an empty fold. Here: engage BOTH config and rules sources, clear ONLY the
    config source, and assert halted is still True because rules are still
    unloaded. If this ever goes False, the fail-open is back.
    """
    pm, _ = make_policy()
    pm._config_halted = True
    pm._rules_loaded = False       # rule fold failed to load

    # Simulate a successful config apply clearing ONLY its own source.
    pm._config_halted = False

    assert pm.halted is True       # still halted: rules never loaded


def test_unhalts_only_when_all_sources_clear():
    """The positive control: with all three sources clear, halted is False.

    Without this, code that always returned True would pass every test above
    while making the bot permanently inert.
    """
    pm, _ = make_policy()
    pm._config_halted = False
    pm._rules_loaded = True
    pm._psl_halt_reason = ""
    assert pm.halted is False


# ===========================================================================
# THEME B -- the schema gate. Fail-closed version bounds.
# ===========================================================================


def test_schema_version_non_int_halts():
    """A non-integer schema_version halts."""
    pm, _ = make_policy()
    pm._apply_auto_config({"schema_version": "2", "recommendation": "m.ban"})
    assert pm.halted is True


def test_schema_version_bool_halts_the_bool_as_int_trap():
    """schema_version: true must halt -- isinstance(True, int) is True in Python.

    The dedicated bool guard exists precisely because a bool passes an int
    check. If that guard is removed, `schema_version: true` would be read as
    version 1 and silently accepted. This pins the trap shut.
    """
    pm, _ = make_policy()
    pm._apply_auto_config({"schema_version": True, "recommendation": "m.ban"})
    assert pm.halted is True


def test_schema_version_below_one_halts():
    """Zero/negative schema_version is malformed -> halt."""
    pm, _ = make_policy()
    pm._apply_auto_config({"schema_version": 0, "recommendation": "m.ban"})
    assert pm.halted is True


def test_schema_version_above_max_halts():
    """A schema_version newer than this bot understands -> halt (upgrade)."""
    pm, _ = make_policy()
    pm._apply_auto_config(
        {"schema_version": pol.MAX_SUPPORTED_SCHEMA_VERSION + 1,
         "recommendation": "m.ban"}
    )
    assert pm.halted is True


def test_valid_v1_config_unhalts_config_source():
    """The positive control: a valid v1 config clears the config halt source.

    (rules still unloaded, so pm.halted overall may stay True -- assert the
    CONFIG source specifically cleared.)
    """
    pm, _ = make_policy()
    pm._apply_auto_config(_v1())
    assert pm._config_halted is False


def test_recommendation_missing_halts():
    """recommendation is load-bearing (hashed into keys); absent/empty -> halt."""
    pm, _ = make_policy()
    pm._apply_auto_config({"schema_version": 1})           # no recommendation
    assert pm.halted is True
    pm._apply_auto_config({"schema_version": 1, "recommendation": ""})
    assert pm.halted is True


# ===========================================================================
# THEME C -- parse_bot_version + the version floor.
# ===========================================================================


def test_parse_bot_version_valid():
    assert parse_bot_version("0.1.9") == (0, 1, 9)
    assert parse_bot_version("1.0.0") == (1, 0, 0)


def test_parse_bot_version_beats_lexical_bug():
    """The whole reason for tuple parsing: (0,1,9) < (0,1,12).

    A lexical string compare has "0.1.9" > "0.1.12" (because '9' > '1'), which
    would fail a floor OPEN -- letting through the outdated bot the floor exists
    to exclude. Parsing to int tuples makes the comparison correct.
    """
    assert parse_bot_version("0.1.9") < parse_bot_version("0.1.12")


def test_parse_bot_version_rejects_non_str():
    """Non-str inputs return None, never raise.

    auto_config is arbitrary JSON: 0.1 arrives as float, true as bool. re.match
    on a non-str RAISES, which would escape _apply_auto_config instead of
    halting cleanly, so the isinstance guard is load-bearing.
    """
    assert parse_bot_version(0.1) is None
    assert parse_bot_version(True) is None
    assert parse_bot_version(None) is None


def test_parse_bot_version_rejects_malformed_strings():
    """Narrower-than-semver grammar: no v-prefix, no 2-seg, no pre-release."""
    assert parse_bot_version("v1.0.0") is None
    assert parse_bot_version("1.0") is None
    assert parse_bot_version("1.0.0-rc1") is None
    assert parse_bot_version("") is None


def test_version_floor_absent_no_gate():
    """No min_bot_version -> the floor never runs (opt-in), even for old bots."""
    pm, _ = make_policy(own_version="0.0.1")
    pm._apply_auto_config(_v2())                # no min_bot_version
    assert pm._config_halted is False           # not halted by a floor


def test_version_floor_below_halts():
    """Bot below the configured floor -> halt (the gate working)."""
    pm, _ = make_policy(own_version="0.1.0")
    pm._apply_auto_config(_v2(min_bot_version="9.9.9"))
    assert pm.halted is True


def test_version_floor_met_proceeds():
    """Bot at/above the floor -> not halted by it."""
    pm, _ = make_policy(own_version="9.9.9")
    pm._apply_auto_config(_v2(min_bot_version="1.0.0"))
    assert pm._config_halted is False


def test_version_floor_malformed_halts_not_ignored():
    """A malformed min_bot_version HALTS -- the deliberate exception to the
    warn-and-disable rule.

    Dropping this field would remove a restriction the operator explicitly
    requested, turning the bot into exactly the outlier the floor excludes. So
    unlike other soft fields, a malformed floor fails CLOSED.
    """
    pm, _ = make_policy(own_version="9.9.9")
    pm._apply_auto_config(_v2(min_bot_version="not-a-version"))
    assert pm.halted is True


def test_version_floor_unparseable_own_version_halts():
    """If a floor is set but our OWN version is unparseable -> halt.

    We can't prove we clear a floor we can't measure ourselves against.
    """
    pm, _ = make_policy(own_version="weird-dev-build")
    pm._apply_auto_config(_v2(min_bot_version="1.0.0"))
    assert pm.halted is True


# ===========================================================================
# THEME W -- SCHEMA-WINDOW enforcement (Sky's addition).
# ===========================================================================
#
# A key takes effect ONLY if it is active for the version the EVENT declares --
# never this bot's own capability. The failure mode this prevents is fleet
# split-brain: bots on different code reaching different halt/act decisions from
# the same event. These test BOTH directions.


def test_key_active_windowing_unit():
    """key_active: min_bot_version is a v2 key, recommendation lives in both."""
    assert key_active("min_bot_version", 1) is False
    assert key_active("min_bot_version", 2) is True
    assert key_active("recommendation", 1) is True
    assert key_active("recommendation", 2) is True
    assert key_active("totally_made_up_key", 2) is False   # unknown -> inactive


def test_v2_key_in_v1_event_is_INERT_even_when_it_would_halt():
    """THE case Sky asked for: min_bot_version in a v1 event does NOT halt,
    even with an outdated bot.

    min_bot_version is a v2 key. A v1 reader doesn't know it exists. If a
    v2-capable bot honored it while a v1 bot ignored it, the fleet would
    disagree about ONE event -> split-brain. So an outdated bot reading a v1
    event that carries a high floor must proceed (config source clears), because
    that floor legally does not exist at v1.
    """
    pm, _ = make_policy(own_version="0.0.1")           # far below 9.9.9
    pm._apply_auto_config(_v1(min_bot_version="9.9.9"))  # but in a v1 event
    assert pm._config_halted is False                   # <-- NOT halted


def test_same_floor_in_v2_event_DOES_halt():
    """The positive control for the case above: identical floor, v2 event,
    now the key IS active -> halt. Proves the inertness above is about the
    window, not a broken floor.
    """
    pm, _ = make_policy(own_version="0.0.1")
    pm._apply_auto_config(_v2(min_bot_version="9.9.9"))
    assert pm.halted is True


def test_v1_key_still_honored_in_v2_event():
    """The reverse direction: a v1 key (decision_map) is still read at v2.

    v1 keys are not retired (removed is None), so a newer schema must still
    honor them, or upgrading the schema would silently drop governance.
    """
    pm, _ = make_policy()
    pm._apply_auto_config(_v2(decision_map={DANGEROUS: "ban"}))
    assert pm.decide(DANGEROUS) == "ban"       # v1 key took effect at v2


def test_inactive_key_emits_warning(caplog):
    """Pasting a v2 key into a v1 event warns (auto_config_key_inactive).

    Without the warning the mismatch is silent: operator sets a floor, gets no
    effect, no complaint. The warning is the tripwire that makes it visible.
    """
    import logging
    pm, _ = make_policy()
    with caplog.at_level(logging.WARNING):
        pm._apply_auto_config(_v1(min_bot_version="9.9.9"))
    assert any("requires schema_version" in r.message for r in caplog.records)


def test_retired_key_ignored_after_its_removal_version(monkeypatch):
    """A key RETIRED in an earlier schema is ignored in a later event.

    No key has actually been retired yet (every `removed` is None), so this
    tests the RETIREMENT MECHANISM against a fictional key with window
    [1, 2) -- introduced in v1, removed as of v2. The property, symmetric to the
    v2-key-in-v1 case: a key must be evaluated IFF it is active for the version
    the EVENT declares, so a key whose window ended before v2 must be inert in a
    v2 event even though the bot still has code to parse it. Same fleet-agreement
    reasoning: bots must agree on which keys an event's declared version
    activates, regardless of what parse code any given bot still carries.

    Implemented by injecting the fictional retired key into SCHEMA_FIELDS for the
    duration of the test (torn down by monkeypatch), then asserting key_active
    reflects the window on both sides of the boundary.
    """
    from csreg_scanner import policy as _pol

    patched = dict(_pol.SCHEMA_FIELDS)
    patched["legacy_thing"] = (1, 2)     # introduced v1, removed as of v2
    monkeypatch.setattr(_pol, "SCHEMA_FIELDS", patched)

    # Active in v1 (its introduction), inert from v2 onward (its removal).
    assert _pol.key_active("legacy_thing", 1) is True
    assert _pol.key_active("legacy_thing", 2) is False
    assert _pol.key_active("legacy_thing", 3) is False
    # And a still-live key is unaffected by the patch.
    assert _pol.key_active("recommendation", 2) is True


# ===========================================================================
# THEME D -- the PSL floor (reevaluate_psl_floor).
# ===========================================================================


def _psl_dt(y, m, d):
    return datetime(y, m, d, tzinfo=timezone.utc)


def test_psl_floor_no_cap_never_halts():
    """No max_bans_per_etld1 -> the suffix list isn't used, so no floor halt."""
    pm, _ = make_policy(psl_holder=FakeHolder(None))
    pm.max_bans_per_etld1 = None
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is False


def test_psl_floor_cap_set_no_list_halts():
    """A cap configured with NO list at all -> halt (unenforceable cap)."""
    pm, _ = make_policy(psl_holder=FakeHolder(None))
    pm.max_bans_per_etld1 = 5
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is True


def test_psl_floor_list_older_than_floor_halts():
    """An active list older than min_psl_version -> halt."""
    old = FakePSL(version=_psl_dt(2026, 1, 1), version_raw="2026-01-01")
    pm, _ = make_policy(psl_holder=FakeHolder(old))
    pm.max_bans_per_etld1 = 5
    pm.min_psl_version = _psl_dt(2026, 7, 1)
    pm.min_psl_version_raw = "2026-07-01"
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is True


def test_psl_floor_list_meets_floor_clears():
    """An active list at/after the floor -> no halt (positive control)."""
    fresh = FakePSL(version=_psl_dt(2026, 8, 1), version_raw="2026-08-01")
    pm, _ = make_policy(psl_holder=FakeHolder(fresh))
    pm.max_bans_per_etld1 = 5
    pm.min_psl_version = _psl_dt(2026, 7, 1)
    pm.min_psl_version_raw = "2026-07-01"
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is False


def test_psl_floor_unorderable_version_treated_as_below_floor():
    """'I cannot tell' is NOT 'I am fine': an active list with no parseable
    VERSION, when a floor is set, HALTS.

    The fail-closed-on-ambiguity rule. If this ever flips to 'unknown version
    passes the floor', an under-informed bot becomes the fleet's weak link --
    the exact thing the floor exists to prevent.
    """
    unversioned = FakePSL(version=None, version_raw=None, source="vendored")
    pm, _ = make_policy(psl_holder=FakeHolder(unversioned))
    pm.max_bans_per_etld1 = 5
    pm.min_psl_version = _psl_dt(2026, 7, 1)
    pm.min_psl_version_raw = "2026-07-01"
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is True


# ===========================================================================
# THEME E -- decide + reconcile. Where a decision becomes a WRITE.
# ===========================================================================


def test_decide_universal_floor():
    """decide floors anything not positively ban/unban to hold."""
    pm, _ = make_policy()
    pm.decision_map = {DANGEROUS: "ban", CLOSED: "unban"}
    pm.default_action = "hold"
    assert pm.decide(DANGEROUS) == "ban"
    assert pm.decide(CLOSED) == "unban"
    assert pm.decide("some_unmapped_status") == "hold"   # floor to hold


def _ready(pm):
    """Put a manager into a writable state: config applied, rules loaded, no PSL
    halt. Used by reconcile/cleanup tests that need writes ENABLED so a
    suppressed write proves a guard, not just the halt.
    """
    pm._apply_auto_config(_v1(decision_map={DANGEROUS: "ban", CLOSED: "unban"}))
    pm._rules_loaded = True


async def test_reconcile_halted_never_writes():
    """Guard 0, the master check: while halted, reconcile writes nothing.

    Arguably the single most important reconcile test. A halted bot handed a
    ban-worthy status must not touch the room.

    CRITICAL setup detail: the manager is configured to BAN (decision map maps
    dangerously_open -> ban, rules loaded) and THEN forced halted via an
    independent source (the PSL halt). This isolates the halt gate as the SOLE
    barrier -- so if the halt check were removed, a write WOULD happen and this
    test bites. An earlier version left the bot unconfigured, so `decide` fell
    to hold and a *different* guard silently masked the halt gate; the test
    passed even with the halt check sabotaged, giving false confidence. Verified
    via mutation: bypassing the halt check now turns this red.
    """
    pm, client = make_policy()
    _ready(pm)                          # fully configured to ban
    assert pm.decide(DANGEROUS) == "ban"
    # Force halt via a source that does NOT touch the decision map, so the halt
    # gate is the only thing between the dangerous status and a write.
    pm._psl_halt_reason = "forced halt for test"
    assert pm.halted is True

    await pm.reconcile("evil.example", DANGEROUS)
    assert client.writes == []          # halt gate alone stops the write


async def test_reconcile_bans_when_ready_and_dangerous():
    """Positive control: ready + dangerous status -> a ban IS written.

    Without this, a bot that never wrote would pass every "no write" test.
    """
    pm, client = make_policy()
    _ready(pm)
    await pm.reconcile("evil.example", DANGEROUS)
    assert len(client.writes) == 1
    _key, content = client.writes[0]
    assert content["entity"] == "evil.example"
    assert content["recommendation"] == "m.ban"


async def test_reconcile_hold_status_no_write():
    """A status that resolves to hold writes nothing."""
    pm, client = make_policy()
    _ready(pm)
    await pm.reconcile("some.example", "oauth")   # unmapped -> default hold
    assert client.writes == []


async def test_reconcile_hold_listed_target_no_write():
    """An explicitly hold-listed domain is inert regardless of status."""
    pm, client = make_policy()
    _ready(pm)
    pm.hold_targets = frozenset({"evil.example"})
    await pm.reconcile("evil.example", DANGEROUS)   # would ban, but held
    assert client.writes == []


async def test_reconcile_ip_literal_skipped_when_disabled():
    """An IP-literal target isn't written when write_policies_for_ip_literals
    is False (the default), even if dangerous."""
    pm, client = make_policy()
    _ready(pm)
    assert pm.write_policies_for_ip_literals is False
    await pm.reconcile("1.2.3.4", DANGEROUS)
    assert client.writes == []


async def test_reconcile_unban_blocked_by_sibling_ban():
    """THE unban-erosion guard: an unban is refused while a sibling under the
    same domain still resolves to ban.

    matrix.example (dangerously_open -> ban) must block an unban triggered by
    matrix.example:8888 (closed -> unban). Mirror of db.py's ban-erosion guard:
    a flapping domain stays banned while ANY of its targets is still dangerous.
    """
    # domain_statuses reports a still-dangerous sibling under the domain.
    async def ds(domain):
        return [("matrix.example", DANGEROUS), ("matrix.example:8888", CLOSED)]

    pm, client = make_policy(domain_statuses=ds)
    _ready(pm)
    # Pre-seed an existing ban rule for the domain so an unban has something to
    # remove (else "not currently banned" short-circuits before the guard).
    key = pm._state_key("matrix.example")
    pm._rules[key] = {"entity": "matrix.example", "recommendation": "m.ban",
                      "reason": "x"}

    await pm.reconcile("matrix.example:8888", CLOSED)   # would unban
    assert client.writes == []          # refused: sibling still dangerous


async def test_reconcile_unban_proceeds_when_no_sibling_ban():
    """Positive control: with no ban-mapped sibling, the unban IS written."""
    async def ds(domain):
        return [("matrix.example:8888", CLOSED)]        # only the closed one

    pm, client = make_policy(domain_statuses=ds)
    _ready(pm)
    key = pm._state_key("matrix.example")
    pm._rules[key] = {"entity": "matrix.example", "recommendation": "m.ban",
                      "reason": "x"}

    await pm.reconcile("matrix.example:8888", CLOSED)
    assert len(client.writes) == 1
    _k, content = client.writes[0]
    assert content == {}                # empty content == rule removal


async def test_reconcile_etld1_cap_refuses_new_ban():
    """The per-eTLD+1 cap: a new ban is refused (fail-loud) at the cap.

    Seed the fold with `cap` existing bans under one eTLD+1, then a new ban for
    a sibling domain must be refused (no write). The refusal is loud (logged),
    but the fail-safe assertion is simply: no over-cap ban is written.
    """
    fresh = FakePSL(version=_psl_dt(2026, 8, 1), version_raw="2026-08-01")
    pm, client = make_policy(psl_holder=FakeHolder(fresh))
    _ready(pm)
    pm.max_bans_per_etld1 = 2
    pm.reevaluate_psl_floor()
    assert pm.psl_floor_halted is False
    # Two existing bans under evil.example (same eTLD+1 by the FakePSL rule).
    for host in ("a.evil.example", "b.evil.example"):
        pm._rules[pm._state_key(host)] = {
            "entity": host, "recommendation": "m.ban", "reason": "x"}

    await pm.reconcile("c.evil.example", DANGEROUS)   # would be the 3rd
    assert client.writes == []          # refused at cap


# ===========================================================================
# THEME F -- glob translation + covering-glob + eTLD+1 counting.
# ===========================================================================


def test_glob_to_regex_dot_is_literal():
    """A '.' in a glob is a LITERAL dot, not any-char.

    Classic glob bug: treating '.' as regex any-char makes 'a.example' match
    'aXexample'. Assert the literal.
    """
    rx = pol._glob_to_regex("a.example")
    assert rx.match("a.example")
    assert not rx.match("aXexample")


def test_glob_to_regex_star_and_question():
    """* matches any run (incl. dots); ? matches exactly one char."""
    star = pol._glob_to_regex("*.evil.example")
    assert star.match("a.b.evil.example")
    q = pol._glob_to_regex("a?.example")
    assert q.match("ab.example")
    assert not q.match("abc.example")


async def test_reconcile_ban_suppressed_by_covering_glob():
    """A ban covered by an existing wildcard rule is not re-written."""
    pm, client = make_policy()
    _ready(pm)
    # Existing glob rule covering the namespace.
    pm._rules[pm._state_key("*.evil.example")] = {
        "entity": "*.evil.example", "recommendation": "m.ban", "reason": "x"}

    await pm.reconcile("host.evil.example", DANGEROUS)
    assert client.writes == []          # suppressed by the covering glob


# ===========================================================================
# THEME G -- stale cleanup guards.
# ===========================================================================


def _cleanup_ready(pm, client):
    """Enable the cleanup lane: age threshold + this bot named as a cleaner.

    The decision_map maps dangerously_open -> ban so the sibling-ban guard tests
    have a status that actually resolves to `ban`. Without this mapping the
    guard can never fire, because it operates on the DECISION, not the raw
    status -- a subtlety worth encoding here so every cleanup test shares a
    realistic map.
    """
    pm._apply_auto_config(_v2(
        decision_map={UNKNOWN: "hold", DANGEROUS: "ban"},
        stale_max_age=100,
        cleanup_bot_ids=[client.mxid],
    ))
    pm._rules_loaded = True


async def test_cleanup_disabled_when_not_named():
    """Cleanup is inert unless this bot is in cleanup_bot_ids."""
    pm, client = make_policy()
    pm._apply_auto_config(_v2(stale_max_age=100, cleanup_bot_ids=["@other:x.org"]))
    pm._rules_loaded = True
    assert pm.cleanup_enabled is False


async def test_cleanup_removes_stale_unknown_rule():
    """Positive control: an old-enough unknown rule IS removed when enabled."""
    pm, client = make_policy()
    _cleanup_ready(pm, client)
    key = pm._state_key("stale.example")
    pm._rules[key] = {"entity": "stale.example", "recommendation": "m.ban",
                      "reason": "x"}
    # status_since far in the past -> age exceeds threshold.
    removed = await pm.consider_stale_cleanup("stale.example", UNKNOWN, 1)
    assert removed is True
    assert client.writes == [(key, {})]     # empty content == removal


async def test_cleanup_refuses_when_too_young():
    """A rule that hasn't been unknown long enough is not removed."""
    pm, client = make_policy()
    _cleanup_ready(pm, client)
    key = pm._state_key("young.example")
    pm._rules[key] = {"entity": "young.example", "recommendation": "m.ban",
                      "reason": "x"}
    # status_since = now -> age ~0 < threshold.
    removed = await pm.consider_stale_cleanup("young.example", UNKNOWN, pol.now())
    assert removed is False
    assert client.writes == []


async def test_cleanup_refuses_non_unknown_status():
    """Only `unknown` ages out; a classified status is reconcile's job."""
    pm, client = make_policy()
    _cleanup_ready(pm, client)
    removed = await pm.consider_stale_cleanup("x.example", CLOSED, 1)
    assert removed is False


async def test_cleanup_blocked_by_sibling_ban():
    """Cleanup reuses the unban guard: a stale sibling can't drop a rule the
    domain still pins as dangerous."""
    async def ds(domain):
        return [("matrix.example", DANGEROUS)]

    pm, client = make_policy(domain_statuses=ds)
    _cleanup_ready(pm, client)
    key = pm._state_key("matrix.example")
    pm._rules[key] = {"entity": "matrix.example", "recommendation": "m.ban",
                      "reason": "x"}
    removed = await pm.consider_stale_cleanup("matrix.example:8888", UNKNOWN, 1)
    assert removed is False
    assert client.writes == []


async def test_cleanup_allowed_when_sibling_resolves_to_non_ban():
    """The INVERSE / positive control: a sibling that resolves to NON-ban does
    NOT block cleanup.

    The guard must block only when a sibling is genuinely ban-mapped -- not
    whenever any sibling merely exists. Here the sibling resolves to `unban`
    (closed -> unban in the map), so there is no ban to pin the rule, and the
    stale unknown rule SHOULD be removable. This proves the guard is precise
    (blocks on danger) rather than over-broad (blocking on mere presence), which
    would otherwise let stale rules accumulate forever whenever any sibling
    existed.
    """
    async def ds(domain):
        return [("matrix.example", CLOSED)]     # closed -> unban, NOT a ban

    pm, client = make_policy(domain_statuses=ds)
    _cleanup_ready(pm, client)
    key = pm._state_key("matrix.example")
    pm._rules[key] = {"entity": "matrix.example", "recommendation": "m.ban",
                      "reason": "x"}
    removed = await pm.consider_stale_cleanup("matrix.example:8888", UNKNOWN, 1)
    assert removed is True                       # no ban-mapped sibling -> allowed
    assert client.writes == [(key, {})]          # rule removed


async def test_cleanup_allowed_when_sibling_is_hold_unknown():
    """A sibling resolving to HOLD (unknown) does NOT block cleanup.

    The third status bucket, completing the trio with the ban (blocks) and unban
    (allows) cases above. `unknown` maps to `hold`, and _domain_has_ban only
    trips on a `ban` decision, so a hold sibling does not pin the rule and
    cleanup proceeds.

    Mechanism (stated precisely, because it is easy to get wrong): a banned
    server that goes UNREACHABLE does not keep its dangerously_open status. An
    unreachable scan returns ok=True/status=unknown (the connection error is
    caught inside classify()), and record_scan's `if ok:` branch overwrites
    reg_status to `unknown`. The ban RULE is nonetheless not lifted, because
    decide("unknown") == "hold" and reconcile writes nothing on hold -- the rule
    sits untouched while the status underneath reads unknown.

    Why cleanup then retiring that rule is CORRECT, not erosion: every rule on
    the list exists because the operator decided that server was dangerous. So
    "retire rules that have been unknown for stale_max_age" necessarily means
    "retire rules that were once for dangerous servers" -- there is no other kind
    of rule to retire, and a cleanup lane that refused to touch anything ever
    ban-mapped would never clean anything, defeating its entire purpose. The
    stale_max_age window (e.g. 60 days) is not "how long until we stop caring
    about a threat" but "how long continuously offline before we conclude the
    server is DEAD rather than temporarily down" -- at which point keeping a ban
    rule for a nonexistent server is just list bloat. Retiring it is hygiene.

    This is therefore intended, time-gated retirement of a rule for a presumed-
    dead server -- categorically different from ban-erosion (the unintended,
    silent loss of a ban that should still stand, which record_scan's ok=False
    preserve branch and the unknown->hold mapping both guard against).
    """
    async def ds(domain):
        return [("matrix.example", UNKNOWN)]    # unknown -> hold, NOT a ban

    pm, client = make_policy(domain_statuses=ds)
    _cleanup_ready(pm, client)
    key = pm._state_key("matrix.example")
    pm._rules[key] = {"entity": "matrix.example", "recommendation": "m.ban",
                      "reason": "x"}
    removed = await pm.consider_stale_cleanup("matrix.example:8888", UNKNOWN, 1)
    assert removed is True                       # hold sibling does not pin
    assert client.writes == [(key, {})]          # rule removed


async def test_cleanup_halted_never_writes():
    """While halted, cleanup writes nothing (covers the version gate too)."""
    pm, client = make_policy()
    # not ready -> halted
    removed = await pm.consider_stale_cleanup("x.example", UNKNOWN, 1)
    assert removed is False
    assert client.writes == []


# ===========================================================================
# THEME H -- 429 retry-after parsing (timing, mild).
# ===========================================================================


def test_retry_after_parses_server_hint():
    """A retry_after_ms hint in the error message is honored (ms -> s)."""
    from mautrix.errors import MLimitExceeded
    exc = MLimitExceeded(400, '{"retry_after_ms": 2000}')
    delay = pol._retry_after_seconds(exc, attempt=0)
    assert delay == 2.0


def test_retry_after_falls_back_to_exponential():
    """With no hint, fall back to bounded exponential backoff."""
    from mautrix.errors import MLimitExceeded
    exc = MLimitExceeded(400, "no hint here")
    d0 = pol._retry_after_seconds(exc, attempt=0)
    d1 = pol._retry_after_seconds(exc, attempt=1)
    assert d1 > d0                       # grows with attempts
    assert d1 <= pol._RL_MAX_BACKOFF     # clamped


def test_retry_after_clamped_to_max():
    """An absurd server hint is clamped to the ceiling."""
    from mautrix.errors import MLimitExceeded
    exc = MLimitExceeded(400, '{"retry_after_ms": 99999999}')
    delay = pol._retry_after_seconds(exc, attempt=0)
    assert delay == pol._RL_MAX_BACKOFF


# ===========================================================================
# THEME I -- load_rules fold preservation (documented past fail-open).
# ===========================================================================


async def test_load_rules_failure_preserves_old_fold_and_stays_halted():
    """A read failure must leave rules_loaded False AND the old fold intact.

    The documented fail-open: the old code cleared the fold first, then returned
    quietly on error -> empty fold with writes enabled, disabling three guards
    at once. Assert a failing get_state leaves the previous fold untouched and
    the bot halted on the rules source.
    """
    # Seed a manager with an existing fold.
    pm, _ = make_policy()
    pm._rules = {"existing_key": {"entity": "keep.example",
                                  "recommendation": "m.ban", "reason": "x"}}
    pm._rules_loaded = True

    # Now swap in a client whose get_state raises.
    pm.client = FakeClient(state=RuntimeError("homeserver down"))
    ok = await pm.load_rules()

    assert ok is False
    assert pm._rules_loaded is False                     # halts on rules source
    assert "existing_key" in pm._rules                   # old fold preserved


async def test_load_rules_success_builds_fold():
    """A successful load builds the fold from m.policy.rule.server state."""
    from mautrix.types import StateEvent
    # A minimal state event of the right type.
    evt = StateEvent.deserialize({
        "type": "m.policy.rule.server",
        "state_key": "abc",
        "sender": "@op:example.org",
        "event_id": "$1",
        "room_id": "!room:example.org",
        "origin_server_ts": 0,
        "content": {"entity": "evil.example", "recommendation": "m.ban",
                    "reason": "x"},
    })
    pm, _ = make_policy(client=FakeClient(state=[evt]))
    ok = await pm.load_rules()
    assert ok is True
    assert pm._rules_loaded is True
    assert pm._rules.get("abc", {}).get("entity") == "evil.example"


def test_scannable_entities_drops_globs_and_invalid():
    """scannable_entities returns real hostnames, dropping globs and junk."""
    pm, _ = make_policy()
    pm._rules = {
        "k1": {"entity": "evil.example", "recommendation": "m.ban"},
        "k2": {"entity": "*.wild.example", "recommendation": "m.ban"},  # glob
        "k3": {},                                                        # tombstone
        "k4": {"entity": "not a valid name!!", "recommendation": "m.ban"},
    }
    out = pm.scannable_entities()
    assert "evil.example" in out
    assert "*.wild.example" not in out
    assert "not a valid name!!" not in out
