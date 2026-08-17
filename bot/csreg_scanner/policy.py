"""Policy governance + writes.

Holds the shared `auto_config` state (read from the policy-list room), enforces
the fail-closed schema gate and the recommendation tripwire, resolves scan
statuses to ban/unban/hold, and performs the actual policy-list writes with a
local-state no-op guard and a write-rate throttle.

Universal floor: anything not positively understood as `ban` or `unban`
resolves to hold / no-write. The worst a malformed auto_config can do (within a
known schema) is make the bot NOT act -- never take a wrong action.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, Callable, Protocol

from mautrix.client import Client
from mautrix.errors import MatrixRequestError, MLimitExceeded, MNotFound
from mautrix.types import EventType, RoomID, StateEvent

from .psl import PSLHolder, PublicSuffixList, parse_psl_version
from .util import is_ip_literal, now, strip_port, validate_server_name

ACTIONS = frozenset({"ban", "unban", "hold"})
POLICY_RULE_SERVER = EventType.find(
    "m.policy.rule.server", t_class=EventType.Class.STATE
)


class DomainStatusProvider(Protocol):
    """Async accessor the unban guard uses to look up every (scan_target,
    reg_status) recorded for scan targets sharing a portless domain. Satisfied
    by db.DB.statuses_for_domain."""

    async def __call__(self, domain: str) -> list[tuple[str, str]]:
        ...

# Dev-owned compatibility ceiling. Intentionally NOT a config option: whether
# this code can correctly interpret a given auto_config schema is a property of
# the codebase, not something a deploying operator can assess. Bump only when a
# reader for the new schema actually ships, and retain readers for all older
# versions (a vN bot must still read v1..vN).
#
# v2 adds five OPTIONAL fields, all inert when absent, so a v1-shaped event
# relabelled `schema_version: 2` behaves identically to v1:
#   min_bot_version    "N.N.N" -- bots below this floor halt (noop mode)
#   stale_max_age      int seconds -- age at which an `unknown` entry is cleanable
#   cleanup_bot_ids    [mxid]  -- which bots may actually perform that cleanup
#   max_bans_per_etld1 int -- per-eTLD+1 ban cap (the thing the floor guards)
#   min_psl_version    PSL header VERSION stamp -- bots whose active public suffix
#                      list is older than this halt
#
MAX_SUPPORTED_SCHEMA_VERSION = 2

# Schema field lifecycle. The single authoritative record of every key the
# auto_config event has ever defined, and the version window each is live in:
#
#   introduced -- first schema version the key is read in (INCLUSIVE)
#   removed    -- first schema version the key is NO LONGER read in (EXCLUSIVE),
#                 or None while the key is still current
#
# so a key live in v2..v4 and retired in v5 is (2, 5): active at 4, gone at 5.
#
# A key is evaluated IFF it is active for the schema THE EVENT DECLARES, never
# this bot's own capability ceiling. A newer bot reading an older event
# evaluates every key against the older number, so a key still live in that
# older version is honoured even though the bot also knows it is later retired.
# Otherwise this bot would become incompatible with older schemas.
#
# Every other case -- key too new for the event, key already retired, key never
# defined, key misspelled -- is ignored identically. That is this bot's existing
# "ignore unknown keys" stance, so deprecation adds NO new code path: a closed
# window and an unrecognised key reach the parser the same way.
#
# Retiring a key sets `removed`; the key's PARSE BLOCK stays as long as the bot
# still reads any event version in the key's window (key_active serves both --
# true on an old-enough event, false on a newer one, same handler). A parse
# block only becomes truly removable if a future MINIMUM supported version is
# raised past the key's `removed`, which is a separate, deliberate decision.
# Retired rows stay in this table: they document the window and keep it a full
# history rather than just the live set.
#
# Dev-owned schema shape, beside MAX_SUPPORTED_SCHEMA_VERSION and NOT operator
# config. This table gates PRESENCE-in-schema only; per-field value validation
# (types, ranges) stays in each parse block, a separate concern.
SCHEMA_FIELDS: dict[str, tuple[int, int | None]] = {
    # key                               (introduced, removed)
    "recommendation":                   (1, None),
    "default_action":                   (1, None),
    "decision_map":                     (1, None),
    "hold_targets":                     (1, None),
    "write_policies_for_ip_literals":   (1, None),
    "ban_reason":                       (1, None),
    # --- v2 additions ---
    "min_bot_version":                  (2, None),
    "stale_max_age":                    (2, None),
    "cleanup_bot_ids":                  (2, None),
    "max_bans_per_etld1":               (2, None),
    "min_psl_version":                  (2, None),
}


def key_active(name: str, version: int) -> bool:
    """True iff `name` is a defined, non-retired field for schema `version`.

    `version` MUST be the event's declared schema_version -- already parsed and
    bounds-checked -- not this bot's capability ceiling. Every caller therefore
    has to run AFTER the schema_version gate in _apply_auto_config; calling it
    with an unvalidated version would let a field be read off an event the bot
    should have halted on.

    Unknown keys return False: absent from the table means part of no schema, so
    a typo'd or unrecognised key is ignored like any other.
    """
    window = SCHEMA_FIELDS.get(name)
    if window is None:
        return False
    introduced, removed = window
    return introduced <= version and (removed is None or version < removed)

# --- bot-version floor (auto_config.min_bot_version) -------------------------
# Strict `major.minor.patch`, anchored, integer segments only. Deliberately
# NARROWER than semver: no `v` prefix, no pre-release, no build metadata, no
# 2- or 4-segment forms. Every syntax accepted here would oblige us to implement
# its ordering rules, and pre-release ordering is the subtle corner (1.0.0-rc1
# sorts BELOW 1.0.0, which is easy to invert) -- an inverted comparison fails
# OPEN, letting through exactly the bot the floor exists to exclude. maubot.yaml
# has only ever carried plain N.N.N, so the narrow grammar costs nothing.

_BOT_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_bot_version(raw: Any) -> tuple[int, int, int] | None:
    """Parse a strict N.N.N version string into a comparable (major, minor,
    patch) tuple. Returns None for ANY input that is not exactly that shape --
    the caller decides what rejection means.

    The isinstance check is load-bearing and must come first: auto_config is
    arbitrary JSON from a room, so `min_bot_version: 0.1` arrives as a float and
    `min_bot_version: true` as a bool, and re.match on a non-str raises
    TypeError -- which would escape _apply_auto_config instead of halting
    cleanly. Same discipline as the bool-as-int rejection on schema_version.

    Parsing to a tuple of ints IS the comparison: Python compares tuples
    element-wise, left to right, so (0, 1, 9) < (0, 1, 12) falls out for free
    with no ordering logic of our own to get wrong. That is the whole point --
    a lexical compare has "0.1.9" > "0.1.12" because '9' > '1' at the first
    character of the third segment.

    `\\d+` rather than a width cap keeps 0.1.100 > 0.1.99 true indefinitely
    (Python ints do not overflow). Leading zeros are accepted and normalise via
    int(), so 0.01.12 compares equal to 0.1.12 -- harmless, and not worth a
    special case.
    """
    if not isinstance(raw, str):
        return None
    m = _BOT_VERSION_RE.match(raw.strip())
    if m is None:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


# --- stale-entry cleanup (auto_config.stale_max_age / cleanup_bot_ids) -------
# Cleanup removes a policy rule whose scan target has been `unknown` for longer
# than stale_max_age, so the list does not grow without bound as banned servers
# die. Deliberately a THIRD write lane, not a decision_map action:
# `unknown` almost always maps to hold (that is why these entries accumulate in
# the first place), so cleanup must fire regardless of the decision map. It
# therefore bypasses the normal governance surface and gets its own two gates --
# an age threshold and an explicit bot allow-list -- both of which must be
# present and valid for a single removal to happen.
_STALE_STATUS = "unknown"


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a Matrix policy glob into an anchored regex. Matrix rule globs use
    `*` (any run of characters, including dots) and `?` (exactly one character),
    per the spec's request for glob-style matching on m.policy.rule entities.
    Every other character is matched literally, so a `.` in the pattern is a
    literal dot -- we escape the literal parts and translate only `*`/`?`."""
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    return re.compile("".join(out))

# Fallback ban reason used only if auto_config omits `ban_reason`. The reason on
# a policy rule is a human-facing string and not load-bearing, so a hardcoded
# default is fine; the list fully controls it via auto_config when present.
_DEFAULT_BAN_REASON = "open registration"

# --- rate-limit (HTTP 429 / M_LIMIT_EXCEEDED) retry tunables -----------------
# mautrix's own request loop only auto-retries 502/503/504, NOT 429, and the
# MLimitExceeded exception in mautrix 0.21.0 carries no structured retry_after
# field -- the homeserver's `retry_after_ms` only survives inside the error
# message string. So we handle 429 locally in _write: parse retry_after_ms when
# present, else fall back to bounded exponential backoff. All retries happen
# under the existing _write_lock, so a throttled write blocks other writes
# rather than letting them pile into the same 429 wall.
_RL_MAX_RETRIES = 5          # attempts AFTER the first try before giving up
_RL_BASE_BACKOFF = 1.0       # seconds; first fallback sleep when no hint given
_RL_MAX_BACKOFF = 30.0       # ceiling for any single sleep (server hint or not)
# Matches "retry_after_ms": 1234 in the flattened error message, tolerating
# whitespace/quoting variations. Server-advertised hint is in MILLISECONDS.
_RETRY_AFTER_RE = re.compile(r"retry_after_ms[\"']?\s*[:=]\s*(\d+)")


class PolicyManager:
    def __init__(
        self,
        client: Client,
        room_id: RoomID,
        *,
        auto_config_type: str,
        max_writes_per_second: float,
        known_statuses: frozenset[str],
        log: logging.Logger,
        domain_statuses: "DomainStatusProvider",
        own_version: str | None = None,
        psl_holder: PSLHolder | None = None,
        on_psl_floor_halt: "Callable[[], None] | None" = None,
        psl_auto_update: bool = True,
    ) -> None:
        self.client = client
        self.room_id = room_id
        # This plugin's own version, as a raw string from maubot.yaml via the
        # loader metadata. Kept unparsed here and parsed on demand inside the
        # gate, so an unparseable own version is only ever fatal when a floor is
        # actually configured (see _apply_auto_config).
        self.own_version = own_version
        self.auto_config_type = EventType.find(
            auto_config_type, t_class=EventType.Class.STATE
        )
        self.known_statuses = known_statuses
        self.log = log
        # Async accessor: portless domain -> list of reg_status for every scan
        # target sharing it. Injected (db.statuses_for_domain) so the policy
        # layer doesn't import the DB; backs the cross-target unban guard.
        self._domain_statuses = domain_statuses

        # governance state, refreshed from auto_config. recommendation and
        # ban_reason are fully list-controlled; recommendation
        # is load-bearing for key derivation, so it stays "" until a valid
        # auto_config sets it -- and writes are gated by `halted` until then.
        # Halt has TWO independent sources and they are ANDed by the `halted`
        # property below. Keeping them separate is load-bearing: a successful
        # _apply_auto_config used to clear a single `halted` flag, which would
        # have cleared a rule-fold failure too -- exactly the fail-open this
        # split exists to close (an empty fold silently disables the no-op
        # guard, glob suppression AND the eTLD+1 cap at once).
        self._config_halted: bool = True
        self._config_halt_reason: str = "auto_config not yet read"
        self._rules_loaded: bool = False
        self.recommendation: str = ""
        self.ban_reason: str = _DEFAULT_BAN_REASON
        self.default_action: str = "hold"
        self.decision_map: dict[str, str] = {}
        # auto_config soft fields: targets that always resolve to
        # hold (operator allow-list for open-but-suspend-on-reg servers), and
        # whether to emit policy rules for IP-literal targets at all. Both are
        # list-controlled, default to the safe/no-op side.
        self.hold_targets: frozenset[str] = frozenset()
        self.write_policies_for_ip_literals: bool = False

        # schema v2 stale-cleanup state. Both default to the inert side: no age
        # threshold and an empty allow-list mean cleanup_enabled is False, so an
        # absent/malformed pair silently disables the lane rather than guessing a
        # threshold. Stored in SECONDS, exactly as the event carries it.
        self.stale_max_age_seconds: int | None = None
        self.cleanup_bot_ids: frozenset[str] = frozenset()

        # schema v2 per-eTLD+1 ban cap. None = disabled (unset or malformed), so
        # the cap is opt-in like the other v2 gates. When set, no bot writes a
        # new ban for a target whose registrable domain already holds this many
        # ban rules -- bounding how far one controlling entity can bloat the list
        # (and thus the ACL toward Matrix's max event size). PSL is loaded once
        # here for the eTLD+1 lookup the count needs.
        self.max_bans_per_etld1: int | None = None
        self.min_psl_version: datetime | None = None
        self.min_psl_version_raw: str | None = None
        # The suffix list arrives as a HOLDER, not a parsed list, and not loaded
        # here. The bot owns loading (vendored + cached blob) and refreshing
        # (online fetch) because both are async and both can produce a NEWER list
        # at any time; policy only ever reads holder.current. `None` means no
        # list at all, which is load-bearing only when a cap is configured.
        self._psl_holder: PSLHolder | None = psl_holder
        # Third halt source, alongside _config_halted and _rules_loaded. Owned by
        # neither the config path nor the refresh path, because it depends on BOTH
        # (min_psl_version moves via the state-event handler; the active version
        # moves via the refresh task) -- so it is derived state that both call
        # _reevaluate_psl_floor() to recompute.
        self._psl_halt_reason: str = ""
        self._on_psl_floor_halt = on_psl_floor_halt
        # Only used to phrase halt reasons. Every suffix-list halt is normally
        # transient -- a fetch resolves it -- but with auto-update off there is no
        # fetch, so the same message would describe a permanent state as if it
        # might clear on its own.
        self._psl_auto_update = psl_auto_update

        # local fold of policy room state: state_key -> content (empty = removed)
        self._rules: dict[str, dict[str, Any]] = {}

        # write throttle (distinct from scan concurrency)
        self._min_interval = 1.0 / max_writes_per_second if max_writes_per_second else 0
        self._write_lock = asyncio.Lock()
        self._last_write = 0.0

    # --- halt state ----------------------------------------------------------

    @property
    def halted(self) -> bool:
        """True while ANY halt source is engaged:

          * an invalid or unreadable auto_config
          * a rule fold we could not load
          * a suffix-list problem: a cap configured with no list at all, or an
            active list older than min_psl_version

        Writes check this one predicate, so no source can be cleared by fixing a
        different one -- the bug that shape prevents is a successful
        _apply_auto_config clearing a rule-fold failure, which would let writes
        proceed against an empty fold.
        """
        return (self._config_halted
                or not self._rules_loaded
                or bool(self._psl_halt_reason))

    @property
    def halt_reason(self) -> str:
        if self._config_halted:
            return self._config_halt_reason
        if not self._rules_loaded:
            return "policy room state not loaded"
        if self._psl_halt_reason:
            return self._psl_halt_reason
        return ""

    # --- suffix-list floor ---------------------------------------------------

    @property
    def psl_floor_halted(self) -> bool:
        """True while the suffix-list halt is engaged (no list with a cap set, or
        an active list below min_psl_version).

        Public so the bot can drive its refresh cadence off it without reaching
        into a private attribute: being halted here is precisely the condition a
        faster fetch could resolve.
        """
        return bool(self._psl_halt_reason)

    @property
    def psl(self) -> PublicSuffixList | None:
        """The active suffix list, or None if there is none."""
        return self._psl_holder.current if self._psl_holder is not None else None

    def reevaluate_psl_floor(self) -> None:
        """Recompute the suffix-list halt. Idempotent; safe to call any time.

        Called from BOTH directions, which is why it is a method rather than
        inline logic: _apply_auto_config calls it because min_psl_version can
        move, and the bot's refresh task calls it because the ACTIVE version can
        move. A bot that starts on a too-old cached list is therefore halted and
        then un-halts by itself the moment a fetch lands, with no operator poke.

        The floor is only enforced when a cap is configured. Without a cap the
        suffix list is not used for anything that can go wrong, so demanding a
        version would be a halt with nothing behind it.
        """
        if self.max_bans_per_etld1 is None:
            self._set_psl_halt("")
            return
        active = self.psl
        if active is None:
            self._set_psl_halt(self._psl_reason(
                "max_bans_per_etld1 is set but no public suffix list is "
                "available; refusing to run with an unenforceable cap"
            ))
            return
        if self.min_psl_version is None:
            self._set_psl_halt("")
            return
        if active.version is None:
            # An active list with no parseable VERSION cannot be ordered against
            # the floor. Treat unorderable as below it: the whole point of the
            # floor is that an under-informed bot must not be the fleet's weak
            # link, and "I cannot tell" is not "I am fine".
            self._set_psl_halt(self._psl_reason(
                "min_psl_version is set but the active public suffix list "
                f"carries no parseable VERSION (source: {active.source})"
            ))
            return
        if active.version < self.min_psl_version:
            self._set_psl_halt(self._psl_reason(
                f"public suffix list {active.version_raw} is older than the "
                f"required min_psl_version {self.min_psl_version_raw}"
            ))
            return
        self._set_psl_halt("")

    def _psl_reason(self, reason: str) -> str:
        """Annotate a suffix-list halt that no fetch can clear.

        All three suffix-list halts are recoverable by adopting a newer list, so
        by default they read as temporary. With policy.psl_auto_update off there
        is no refresh task at all, which makes them permanent until the package or
        the config changes -- worth saying in the message rather than leaving
        someone to infer it from the absence of retry lines in the log.
        """
        if self._psl_auto_update:
            return reason
        return reason + " (policy.psl_auto_update is off, so no fetch will "\
                        "recover this)"

    def _set_psl_halt(self, reason: str) -> None:
        """Assign the suffix-list halt, logging only on a TRANSITION.

        Transition-only because reevaluate_psl_floor runs on every config change
        and every refresh tick; logging unconditionally would emit the same line
        daily forever on a healthy bot and hourly on a stuck one.
        """
        if reason == self._psl_halt_reason:
            return
        if reason:
            self.log.error(
                "halting policy writes: %s", reason,
                extra={"csreg_alarm": "psl_floor_halt", "reason": reason},
            )
            # Wake the refresh task. Without this, a min_psl_version bump would
            # not be acted on until the current sleep expired -- up to a full day
            # -- which defeats the point of raising the floor to make the fleet
            # converge quickly. Only on ENGAGE: clearing the halt needs no fetch.
            if self._on_psl_floor_halt is not None:
                try:
                    self._on_psl_floor_halt()
                except Exception:  # noqa: BLE001 -- a notifier must never break policy
                    self.log.debug("psl floor halt notifier failed", exc_info=True)
        else:
            self.log.info(
                "public suffix list satisfies the configured floor; "
                "policy writes may resume",
                extra={"csreg_event": "psl_floor_cleared"},
            )
        self._psl_halt_reason = reason

    # --- auto_config ---------------------------------------------------------

    async def refresh_auto_config(self) -> bool:
        """Read auto_config from the room and validate it.

        Returns whether the READ succeeded -- not whether the bot ended up
        unhalted. The caller's retry loop keys on that distinction: a transport
        failure is worth retrying, whereas a successful read of an absent or
        malformed event is not (the operator has to fix the event, and when they
        do, the live state-event handler applies it immediately). Retrying the
        latter would just log an error every 60s forever for a room that is
        legitimately still being set up.

        After startup the value is kept live by apply_auto_config_event() from
        the bot's state-event handler, so this network read happens at start(),
        on an explicit reload, and on a resync retry -- NOT per scan tick.
        """
        try:
            content = await self.client.get_state_event(
                self.room_id, self.auto_config_type, ""
            )
        except MNotFound:
            # Read succeeded; there is simply no event. Halt, but do not retry.
            self._halt("auto_config state event absent")
            return True
        except MatrixRequestError as e:
            self._halt(f"auto_config unreadable: {e}")
            return False
        except Exception as e:  # noqa: BLE001 -- transport-level failure
            # aiohttp.ClientError / TimeoutError are NOT MatrixRequestError, so
            # without this a homeserver hiccup at start() propagated out of
            # start() and left the plugin dead rather than halted-and-retrying.
            self._halt(f"auto_config unreadable: {type(e).__name__}: {e}")
            return False

        data = _as_dict(content)
        self._apply_auto_config(data)
        return True

    def apply_auto_config_event(self, content: Any) -> None:
        """Apply a live auto_config update delivered as a room state event.
        Called from the bot's state-event handler the moment the operator edits
        the event, so governance changes propagate without a redeploy and
        without per-tick polling."""
        self._apply_auto_config(_as_dict(content))

    @staticmethod
    def _field(data: dict[str, Any], name: str, version: int, default: Any = None) -> Any:
        """Read auto_config field `name` iff it is active for the event's schema
        `version`, else return `default`. The one door through which every
        versioned field is read, so the field name appears exactly once per field
        (table row + this call) and the window lives solely in SCHEMA_FIELDS -- a
        future `removed` needs no edit at the call site.

        `version` is the event's declared, already-validated schema_version, so
        every call sits after the schema gate below. `default` matches each
        field's own empty-shape (None, {}, []) so the parse logic downstream is
        unchanged from the hand-written `if version >= N` form it replaces.
        """
        return data.get(name, default) if key_active(name, version) else default

    def _apply_auto_config(self, data: dict[str, Any]) -> None:
        # --- schema gate, single predicate ----------------------------------
        version = data.get("schema_version")
        if not isinstance(version, int) or isinstance(version, bool):
            self._halt(f"schema_version not an integer: {version!r}")
            return
        # Lower bound: schema versions are 1-based. A zero/negative version is
        # malformed (would otherwise slip past the upper-bound check and be
        # accepted). Fail closed.
        if version < 1:
            self._halt(f"schema_version {version} < 1; malformed")
            return
        if version > MAX_SUPPORTED_SCHEMA_VERSION:
            self._halt(
                f"schema_version {version} > max supported "
                f"{MAX_SUPPORTED_SCHEMA_VERSION}; upgrade required"
            )
            return

        # --- bot-version floor (v2+, optional) -------------------------------
        # Placed immediately after the schema bounds check and before any field
        # is interpreted: a bot the operator has excluded must not act on this
        # event at all, so it halts before reading anything it might misread.
        #
        # ABSENT => no floor, gate never runs. Halting a whole fleet because the
        # operator left a field unset would be the wrong default, so the floor is
        # strictly opt-in.
        #
        # PRESENT BUT UNPARSEABLE => halt. The operator was deliberately trying
        # to force a version floor and we cannot tell which one; treating that as
        # "no floor" would fail open in the exact scenario the floor exists for.
        # This is the one place a malformed SOFT field halts rather than degrading
        # to inert, and it is intentional: a floor is a gate, not a preference.
        # Scoped by the schema field table now, not a bare version check. In v1
        # this key is undefined, so a v1 reader treats it as unknown and ignores
        # it -- and a v2-capable bot has to agree, or the fleet would disagree
        # about one event. _field enforces that window centrally.
        raw_floor = self._field(data, "min_bot_version", version)
        if raw_floor is not None:
            floor = parse_bot_version(raw_floor)
            if floor is None:
                self._halt(
                    f"min_bot_version malformed: {raw_floor!r} "
                    "(expected a \"major.minor.patch\" string)"
                )
                return
            # Our own version goes through the SAME parser, so we never compare a
            # tuple against a foreign object -- loader.meta.version may hand back
            # a packaging Version rather than a str. Failing to parse ourselves
            # also halts: we cannot prove we clear a floor we cannot measure
            # against. Only reachable when a floor is configured, so a plugin with
            # an odd version string is unaffected until someone sets one.
            mine = parse_bot_version(self.own_version)
            if mine is None:
                self._halt(
                    f"min_bot_version {raw_floor!r} is set but this bot's own "
                    f"version is unparseable: {self.own_version!r}"
                )
                return
            if mine < floor:
                # Distinct alarm key: an operator seeing csreg_halted needs to
                # tell "upgrade me" apart from "auto_config is broken".
                self.log.error(
                    "HALT: bot version below configured floor",
                    extra={
                        "csreg_alarm": "version_gate",
                        "own_version": self.own_version,
                        "min_bot_version": raw_floor,
                    },
                )
                self._halt(
                    f"bot version {self.own_version} < min_bot_version "
                    f"{raw_floor}; upgrade required"
                )
                return

        # --- recommendation: fully list-controlled, load-bearing ------------
        # Hashed into every state key, so it MUST be present and a non-empty
        # string before any write. The list is the single source. Absent/empty/non-str
        # => halt (fail-closed: no recommendation, no key derivation, no writes).
        # NOTE: changing this value still orphans every existing rule. That is
        # now an unguarded operator action; it is only protected by the room PL
        # restricting who may write the auto_config event. Don't change it.
        recommendation = self._field(data, "recommendation", version)
        if not isinstance(recommendation, str) or not recommendation:
            self._halt(
                f"recommendation missing or not a non-empty string: {recommendation!r}"
            )
            return
        self.recommendation = recommendation

        # --- soft fields, validated; universal floor toward hold ------------
        # ban_reason flows into rule content as the human-facing `reason`, so it
        # must be a non-empty string; anything else falls back to the default.
        ban_reason = self._field(data, "ban_reason", version)
        self.ban_reason = (
            ban_reason if isinstance(ban_reason, str) and ban_reason
            else _DEFAULT_BAN_REASON
        )

        default_action = self._field(data, "default_action", version, "hold")
        if default_action not in ACTIONS:
            self.log.warning(
                "auto_config default_action invalid; coercing to hold",
                extra={"csreg_alarm": "auto_config_default_action", "value": default_action},
            )
            default_action = "hold"
        self.default_action = default_action

        clean: dict[str, str] = {}
        raw_map = self._field(data, "decision_map", version, {}) or {}
        if isinstance(raw_map, dict):
            for key, action in raw_map.items():
                if key not in self.known_statuses:
                    # per-entry tolerance: drop unknown key, keep the rest
                    self.log.warning(
                        "auto_config decision_map: ignoring unknown status key",
                        extra={"csreg_alarm": "auto_config_unknown_status", "key": key},
                    )
                    continue
                if action not in ACTIONS:
                    self.log.warning(
                        "auto_config decision_map: invalid action -> hold",
                        extra={"csreg_alarm": "auto_config_bad_action", "key": key,
                               "value": action},
                    )
                    action = "hold"
                clean[key] = action
        self.decision_map = clean

        # --- hold-list: domains that ALWAYS resolve to hold  ------------------
        # Operator allow-list for servers that are open-reg on paper but
        # mitigate the danger (e.g. suspend-on-registration). Entries may be
        # written with or without a port, but are matched on the PORTLESS domain
        # because policy rules / ACLs are always applied portless -- a port on a
        # hold entry carries no extra meaning, so a hold covers the whole domain
        # (every port variant). Bad/duplicate entries are dropped and counted.
        # hold means hold: a held domain emits neither ban nor unban, and
        # contributes no `ban` opinion to the unban guard (it is simply inert).
        hold_targets: set[str] = set()
        raw_hold = self._field(data, "hold_targets", version, []) or []
        if isinstance(raw_hold, list):
            dropped = 0
            for item in raw_hold:
                if isinstance(item, str) and validate_server_name(item.strip()):
                    hold_targets.add(strip_port(item.strip()))  # store portless
                else:
                    dropped += 1
            if dropped:
                self.log.warning(
                    "auto_config hold_targets: dropped %d invalid entr(y/ies)",
                    dropped,
                    extra={"csreg_alarm": "auto_config_bad_hold_target",
                           "dropped": dropped},
                )
        elif raw_hold:
            self.log.warning(
                "auto_config hold_targets not a list; ignoring",
                extra={"csreg_alarm": "auto_config_hold_targets_type"},
            )
        self.hold_targets = frozenset(hold_targets)

        # --- IP-literal policy writes: default OFF  --------------------------
        # A Matrix ACL `allow_ip_literals: false` already blankets every IP
        # literal, so a per-IP policy rule is redundant ACL-event-size bloat. 
        # When false we still SCAN literals (status is tracked), we just never 
        # emit a rule for them. Anything other than an explicit True stays False.
        self.write_policies_for_ip_literals = (
            self._field(data, "write_policies_for_ip_literals", version) is True
        )

        # --- stale-entry cleanup (v2+, optional) -----------------------------
        # Three states only, per the operator's spec: SET (a positive integer of
        # SECONDS), UNSET, or MALFORMED -- the latter two both mean "cleanup
        # off". No floor and no default: a malformed value must not silently
        # become some number we invented, because that number would then be
        # deleting rules. Deliberately soft (disable, don't halt), unlike
        # min_bot_version: an absent age threshold cannot cause a WRONG action,
        # only inaction, which is the universal floor this module already keeps.
        #
        # Seconds, not days: every other auto_config field is stored exactly as
        # authored, so a unit conversion here would be the ONLY place the stored
        # value diverges from the event value -- the asymmetry that bites when a
        # state event and the logs disagree. Seconds also let the operator run
        # sub-day experiments (stale_max_age: 300) that a day granularity forbids.
        #
        # The isinstance(int) + not-bool guard is the "whole numbers only" check:
        # 300.0, "300" and True are all rejected, so no fractional or coerced
        # value ever reaches the clock. > 0 rejects 0 and negatives.
        # Windowed by SCHEMA_FIELDS via _field: undefined in v1, so a v1 event
        # never starts any bot removing rules.
        raw_age = self._field(data, "stale_max_age", version)
        if isinstance(raw_age, int) and not isinstance(raw_age, bool) and raw_age > 0:
            self.stale_max_age_seconds = raw_age
        elif raw_age is None:
            self.stale_max_age_seconds = None
        else:
            self.stale_max_age_seconds = None
            self.log.warning(
                "auto_config stale_max_age malformed; stale cleanup disabled",
                extra={"csreg_alarm": "auto_config_bad_stale_max_age",
                       "value": raw_age},
            )

        # Which bots may perform the removal. Exact MXID match against our own
        # client.mxid -- no normalisation beyond a strip, because an MXID is
        # already canonical and guessing at case folding would widen the
        # allow-list. Absent/empty/not-a-list => nobody cleans up (inert).
        # Restricting cleanup to named bots is not a correctness requirement
        # (state writes are idempotent and the local _rules fold makes a double
        # removal a no-op) but an accountability one: one known writer per
        # removal keeps the room's audit trail readable.
        cleanup_ids: set[str] = set()
        raw_ids = self._field(data, "cleanup_bot_ids", version, []) or []
        if isinstance(raw_ids, list):
            dropped = 0
            for item in raw_ids:
                if isinstance(item, str) and item.strip().startswith("@") \
                        and ":" in item.strip():
                    cleanup_ids.add(item.strip())
                else:
                    dropped += 1
            if dropped:
                self.log.warning(
                    "auto_config cleanup_bot_ids: dropped %d invalid entr(y/ies)",
                    dropped,
                    extra={"csreg_alarm": "auto_config_bad_cleanup_bot_id",
                           "dropped": dropped},
                )
        elif raw_ids:
            self.log.warning(
                "auto_config cleanup_bot_ids not a list; ignoring",
                extra={"csreg_alarm": "auto_config_cleanup_bot_ids_type"},
            )
        self.cleanup_bot_ids = frozenset(cleanup_ids)

        # Per-eTLD+1 ban cap. Same three-state discipline as stale_max_age:
        # SET (positive whole number), UNSET, or MALFORMED -- the latter two both
        # disable the cap. Whole-numbers-only via the isinstance(int)+not-bool
        # guard; > 0 rejects 0 and negatives (a cap of 0 would forbid ALL bans,
        # which is never the intent -- disable it instead of setting 0).
        # Windowed by SCHEMA_FIELDS via _field: undefined in v1.
        raw_cap = self._field(data, "max_bans_per_etld1", version)
        if isinstance(raw_cap, int) and not isinstance(raw_cap, bool) and raw_cap > 0:
            self.max_bans_per_etld1 = raw_cap
        elif raw_cap is None:
            self.max_bans_per_etld1 = None
        else:
            self.max_bans_per_etld1 = None
            self.log.warning(
                "auto_config max_bans_per_etld1 malformed; ban cap disabled",
                extra={"csreg_alarm": "auto_config_bad_max_bans_per_etld1",
                       "value": raw_cap},
            )

        # min_psl_version: the suffix-list floor. ABSENT means no floor -- an
        # operator who has not asked for one is not required to have one.
        #
        # MALFORMED halts, which breaks the warn-and-disable convention the other
        # soft fields follow, deliberately: for every other field, dropping it
        # loses a refinement, whereas dropping THIS one removes a restriction
        # that was explicitly requested. A typo would silently turn the bot into
        # exactly the unbounded-ban outlier the floor exists to exclude.
        #
        # Present-but-inactive guard. _field silently returns the default for a
        # key that is not live at the event's declared schema_version, which is
        # right for reading but wrong as the ONLY feedback: an operator who pastes
        # a v2 key into an event still declaring schema_version 1 would get no
        # effect and no complaint. Warn for any such key so the mismatch is
        # visible.
        for key in data:
            if key in SCHEMA_FIELDS and not key_active(key, version):
                introduced, _removed = SCHEMA_FIELDS[key]
                self.log.warning(
                    "auto_config carries %r, which requires schema_version >= %d "
                    "but the event declares %d; it is being IGNORED",
                    key, introduced, version,
                    extra={"csreg_alarm": "auto_config_key_inactive",
                           "key": key, "requires_schema": introduced,
                           "declared_schema": version},
                )

        raw_min_psl = self._field(data, "min_psl_version", version)
        if raw_min_psl is None:
            self.min_psl_version = None
            self.min_psl_version_raw = None
        else:
            try:
                self.min_psl_version = parse_psl_version(raw_min_psl)
                self.min_psl_version_raw = str(raw_min_psl).strip()
            except (ValueError, TypeError):
                self.min_psl_version = None
                self.min_psl_version_raw = None
                if self.max_bans_per_etld1 is not None:
                    self._halt(
                        f"min_psl_version {raw_min_psl!r} is malformed (expected "
                        "a PSL header stamp like 2026-07-25_14-20-03_UTC); "
                        "refusing to run with an unreadable version floor"
                    )
                    return
                self.log.warning(
                    "auto_config min_psl_version malformed; ignored (no ban cap "
                    "is configured, so no floor is required)",
                    extra={"csreg_alarm": "auto_config_bad_min_psl_version",
                           "value": raw_min_psl},
                )

        # Recompute the suffix-list halt now that BOTH the cap and the floor are
        # known. This subsumes the old "cap set but no list" check and adds the
        # version comparison; it is the same function the refresh task calls when
        # a newer list is adopted, so the two directions cannot drift apart.
        self.reevaluate_psl_floor()

        if self._config_halted:
            self.log.info("auto_config valid again; resuming")
        self._config_halted = False
        self._config_halt_reason = ""

    def _halt(self, reason: str) -> None:
        if not self._config_halted or reason != self._config_halt_reason:
            # Structured ERROR is the only artifact left once policy ops stop;
            # it must carry the full reason. Wire csreg_alarm to your logger.
            self.log.error(
                "HALT: policy writes disabled",
                extra={
                    "csreg_alarm": "policy_halt",
                    "reason": reason,
                    "max_supported_schema": MAX_SUPPORTED_SCHEMA_VERSION,
                },
            )
        self._config_halted = True
        self._config_halt_reason = reason

    # --- decision  -----------------------------------------------------------

    def decide(self, status: str) -> str:
        action = self.decision_map.get(status, self.default_action)
        return action if action in ACTIONS else "hold"

    # --- local state fold -----------------------------------------------------

    async def load_rules(self) -> bool:
        """Populate the local rule fold from current room state, so the no-op
        guard is a local lookup, not a C-S API round-trip per server.

        Returns whether the load SUCCEEDED. On failure the bot stays halted
        (self._rules_loaded stays False) and the previous fold is left intact.

        Both of those matter. The old version cleared the fold first and then
        returned quietly on error, leaving an EMPTY fold with writes enabled --
        which simultaneously disabled three guards: every entity looked
        unbanned (re-writing the entire list at the throttle rate), no glob
        looked like it covered anything (redundant explicit bans under existing
        wildcards), and every eTLD+1 counted zero existing bans (cap bypassed).
        Building into a fresh dict and swapping only on success means a
        transient read failure costs nothing but a pause.
        """
        try:
            state = await self.client.get_state(self.room_id)
        except Exception as e:  # noqa: BLE001 -- Matrix OR transport failure
            self._rules_loaded = False
            self.log.error(
                "could not load policy room state; halting until it can be read",
                extra={"csreg_alarm": "policy_rules_unreadable",
                       "error": f"{type(e).__name__}: {e}"},
            )
            return False
        rules: dict[str, dict[str, Any]] = {}
        for evt in state:
            if not isinstance(evt, StateEvent):
                continue
            if str(evt.type) != "m.policy.rule.server":
                continue
            rules[evt.state_key] = _as_dict(evt.content)
        self._rules = rules
        self._rules_loaded = True
        return True

    def active_rules(self) -> int:
        return sum(1 for c in self._rules.values() if c)

    def scannable_entities(self) -> list[str]:
        """Scan targets from the current policy-list fold, for the
        PolicyListSource: every non-tombstoned server rule's `entity`, with glob
        patterns (`*`/`?`) dropped because they are match patterns, not scannable
        hostnames. Rule entities are already portless (rules are keyed portless),
        so these come back as portless scan targets -- which is what we want to
        re-verify. Recommendation-agnostic (all server rules, any recommendation).
        Reads the in-memory fold -- no I/O, no C-S API round-trip. 

        Edge validation (defense in depth): the central _clean gate in bot.py is
        the authority, but we also drop anything here that isn't a valid server
        name so a malformed rule `entity` written by another tool never reaches
        the queue and a perpetual scan-failure is avoided. Dropped entries are
        counted in the log."""
        out: list[str] = []
        seen: set[str] = set()
        dropped = 0
        for content in self._rules.values():
            if not content:  # tombstone (removed rule)
                continue
            entity = content.get("entity")
            if not isinstance(entity, str) or not entity:
                continue
            if "*" in entity or "?" in entity:  # glob pattern, not a host
                continue
            domain = strip_port(entity)
            if not domain or not validate_server_name(domain):
                dropped += 1
                continue
            if domain not in seen:
                seen.add(domain)
                out.append(domain)
        if dropped:
            self.log.debug(
                "policy_list source: skipped %d non-scannable rule entit(y/ies)",
                dropped,
            )
        return out

    def note_rule(self, state_key: str, content: Any) -> None:
        """Keep the local fold live as OTHER writers change the policy room --
        other operators' bots, the self-service bot, manual ops. Called
        from the bot's m.policy.rule.server state-event handler. Empty content
        means the rule was removed (tombstone)."""
        self._rules[state_key] = _as_dict(content)

    # --- writes ----------------------------------------------------------------

    def _state_key(self, entity: str) -> str:
        digest = hashlib.sha256((entity + self.recommendation).encode()).digest()
        return base64.b64encode(digest).decode("ascii")

    async def reconcile(self, scan_target: str, status: str) -> None:
        """Reconcile one scan target's desired policy state with current state.
        No-op unless desired != current. No write while halted -- and
        because the state key depends on auto_config.recommendation, an
        unreadable auto_config means no writes anyway.

        `scan_target` is the full name (with port if any). Policy rules are keyed
        on the PORTLESS domain (one rule per domain), so storage/scan granularity
        (per target) is finer than policy granularity (per domain). Several
        guards layer here before any write:

          1. halted        -> never write.
          2. hold-list      -> target explicitly held: inert, no ban/unban.
          3. decision=hold  -> nothing to do.
          4. IP literal + writes disabled -> skip the write (still scanned; an
             ACL allow_ip_literals:false already covers it).
          5. unban guard    -> an unban is allowed ONLY if no OTHER scan target
             sharing this domain currently resolves to `ban`. So `matrix.org`
             (dangerously_open -> ban) blocks an unban triggered by
             `matrix.org:8888` (closed -> unban). The domain may flap; the guard
             keeps a still-dangerous domain banned.
        """
        if self.halted:
            return

        entity = strip_port(scan_target)  # rules/ACLs/holds are all portless

        # hold-list match is on the PORTLESS domain (ACLs apply portless).
        if entity in self.hold_targets:
            return

        action = self.decide(status)
        if action == "hold": 
            return

        # IP literal: skip the policy WRITE unless explicitly enabled.
        if not self.write_policies_for_ip_literals and is_ip_literal(entity):
            self.log.debug(
                "skipping policy write for IP literal %s (write_policies_for_"
                "ip_literals is false)", entity,
            )
            return

        key = self._state_key(entity)
        currently_banned = bool(self._rules.get(key))

        if action == "ban":
            if not currently_banned:
                # Guard 1 -- glob suppression. If an existing wildcard rule
                # already covers this target, do not add a redundant explicit
                # ban under it. Pure Matrix glob matching against rule entities;
                # no PSL involved. Runs first: a covered target is a full stop,
                # never counted against the cap.
                covering = self._covering_glob(entity)
                if covering is not None:
                    # INFO, not debug: this is the one guard whose outcome an
                    # operator actively wants to see. A suppressed ban here is
                    # the wildcard doing its job -- it is the evidence that a
                    # namespace-level decision is absorbing individual hits, and
                    # it is also how you find out a glob is broader than intended
                    # (an unexpected entity showing up under it). csreg_event
                    # rather than csreg_alarm: nothing is wrong.
                    #
                    # Fires once per scan of a covered target, not once per
                    # target: covered targets never get an explicit rule, so
                    # `currently_banned` stays False and this path is reached on
                    # every rescan. Volume therefore tracks (covered targets x
                    # rescan rate) -- fine for a normal glob, worth knowing about
                    # if a very broad one is in place with a short staleness.
                    self.log.info(
                        "ban for %s suppressed: covered by existing glob %s",
                        entity, covering,
                        extra={"csreg_event": "ban_suppressed_by_glob",
                               "entity": entity, "scan_target": scan_target,
                               "covering_glob": covering,
                               "status": status},
                    )
                    return
                # Guard 2 -- per-eTLD+1 cap. Refuse a new ban once this
                # registrable domain already holds max_bans_per_etld1 ban rules.
                # Fail-LOUD, not silent: the refused ban means a ban-worthy
                # server is now NOT on the list, which the operator must see so a
                # wildcard decision can be made. Disabled when cap is None.
                if (self.max_bans_per_etld1 is not None
                        and self.psl is not None
                        and not is_ip_literal(entity)):
                    etld1, count = self._etld1_ban_count(entity)
                    if count >= self.max_bans_per_etld1:
                        self.log.error(
                            "ban for %s REFUSED: eTLD+1 %s already at cap "
                            "(%d/%d); a wildcard ban may be needed",
                            entity, etld1, count, self.max_bans_per_etld1,
                            extra={"csreg_alarm": "ban_cap_reached",
                                   "entity": entity, "etld1": etld1,
                                   "count": count, "cap": self.max_bans_per_etld1},
                        )
                        return
                await self._write(
                    key, {"entity": entity, "recommendation": self.recommendation,
                           "reason": self.ban_reason}
                )
        elif action == "unban" and currently_banned:
            # cross-target unban guard. Only lift the ban if NO other scan
            # target under this domain still resolves to `ban` under the live
            # decision map. Held targets are excluded from the vote: the operator
            # hold-listed them precisely so their raw status does not act, so
            # letting them pin a ban would defeat the hold-list.
            if await self._domain_has_ban(entity):
                self.log.debug(
                    "unban for %s suppressed: another target under %s still "
                    "resolves to ban", scan_target, entity,
                )
                return
            await self._write(key, {})  # empty-content tombstone == rule removal

    # --- stale-entry cleanup --------------------------------------------------

    @property
    def cleanup_enabled(self) -> bool:
        """True only when BOTH gates are satisfied: an age threshold is configured
        AND this bot is named in cleanup_bot_ids. Either one missing means the
        lane is inert."""
        return (
            self.stale_max_age_seconds is not None
            and str(self.client.mxid) in self.cleanup_bot_ids
        )

    async def consider_stale_cleanup(
        self, scan_target: str, status: str, status_since: int | None
    ) -> bool:
        """Remove this target's policy rule if it has been `unknown` for longer
        than stale_max_age. Returns True only when a removal was actually
        written, so the caller can count it.

        Called on every scan result, immediately after reconcile(), and cheap to
        reject: the common path fails the `status != unknown` test after two
        attribute reads.

        The guard order matters and mirrors reconcile():

          1. halted        -> never write. Covers the version gate too, so an
                              excluded bot cannot clean up either.
          2. gates off     -> no threshold, or we are not an authorised cleaner.
          3. not unknown   -> only `unknown` ages. A live server with a real
                              classification is reconcile()'s business.
          4. no clock      -> status_since absent; cannot age it, so leave it.
          5. too young     -> under the threshold.
          6. hold-list     -> a held domain is inert in BOTH directions; the
                              operator held it deliberately and cleanup must not
                              be a back door that removes its rule anyway.
          7. no rule       -> nothing to remove (local fold, no round-trip).
          8. unban guard   -> reuses _domain_has_ban: a stale matrix.org:8888
                              must not drop the rule for a domain that
                              matrix.org still pins as dangerously_open.

        Note this does NOT touch the `scanned` row. The entry keeps being
        rescanned and keeps its history for stats; only the policy rule goes. If
        the server comes back open it is re-banned by the normal reconcile path
        on the next scan, so a cleanup is never terminal.
        """
        if self.halted:
            return False
        if not self.cleanup_enabled:
            return False
        if status != _STALE_STATUS:
            return False
        if status_since is None:
            return False

        assert self.stale_max_age_seconds is not None  # implied by cleanup_enabled
        age = now() - status_since
        if age < self.stale_max_age_seconds:
            return False

        entity = strip_port(scan_target)
        if entity in self.hold_targets:
            return False

        key = self._state_key(entity)
        if not self._rules.get(key):
            return False

        if await self._domain_has_ban(entity):
            self.log.debug(
                "stale cleanup for %s suppressed: another target under %s still "
                "resolves to ban", scan_target, entity,
            )
            return False

        await self._write(key, {})  # empty content == rule removal
        self.log.info(
            "stale cleanup: removed policy rule for %s after %d seconds unknown",
            entity, age,
            extra={"csreg_event": "stale_cleanup", "entity": entity,
                   "scan_target": scan_target, "unknown_seconds": age},
        )
        return True

    def _covering_glob(self, entity: str) -> str | None:
        """Return the entity of an existing glob rule that covers `entity`, or
        None. Iterates the local fold; a rule is a glob if its entity contains
        `*`/`?`, and it covers `entity` if the Matrix glob matches. Tombstones
        (empty content) and the target's own would-be exact rule are skipped.
        Recommendation-agnostic: a wildcard ban under any recommendation still
        represents an operator decision to cover the namespace."""
        for content in self._rules.values():
            if not content:  # tombstone
                continue
            pat = content.get("entity")
            if not isinstance(pat, str) or ("*" not in pat and "?" not in pat):
                continue
            if _glob_to_regex(pat).match(entity):
                return pat
        return None

    def _etld1_ban_count(self, entity: str) -> tuple[str, int]:
        """Return (etld1, number of existing BAN rules whose entity collapses to
        that same eTLD+1). Counts exact (non-glob) ban rules only: globs are the
        consolidation the cap exists to encourage, so they never count toward it
        (and a target a glob covers was already suppressed by guard 1). Apex and
        subdomains share one eTLD+1 and thus one budget, by design.

        The unknown-TLD fail-safe (psl.etld1 matched=False) makes the host its
        own bucket -- counted but not grouped -- and emits the psl_unknown_tld
        tripwire so a novel TLD is visible in monitoring and can be answered with
        a PSL refresh + min_bot_version bump."""
        psl = self.psl
        assert psl is not None  # guarded by the caller and the halt gate
        target_etld1, matched = psl.etld1(entity)
        if not matched:
            self.log.warning(
                "unknown TLD in %s; PSL may need refreshing (counted but not "
                "grouped)", entity,
                extra={"csreg_alarm": "psl_unknown_tld", "host": entity,
                       "tld": entity.rsplit(".", 1)[-1] if "." in entity else entity},
            )
        count = 0
        for content in self._rules.values():
            if not content:  # tombstone
                continue
            rule_entity = content.get("entity")
            if not isinstance(rule_entity, str) or not rule_entity:
                continue
            if "*" in rule_entity or "?" in rule_entity:  # globs never count
                continue
            if content.get("recommendation") != self.recommendation:
                # Only bans under the ACTIVE recommendation.
                continue
            if is_ip_literal(rule_entity):
                continue  # IP literals have no eTLD+1
            rule_etld1, _ = psl.etld1(rule_entity)
            if rule_etld1 == target_etld1:
                count += 1
        return target_etld1, count

    @property
    def etld1s_at_cap(self) -> int:
        """Number of distinct eTLD+1 buckets currently at or above the ban cap.
        For the metrics gauge -- a nonzero value means at least one controlling
        entity has saturated its budget and new bans under it are being refused,
        which is the operator's cue that a wildcard decision may be pending. 0
        when the cap is disabled. Recomputed from the fold on each scrape; cheap
        at this list size (a few hundred rules)."""
        psl = self.psl
        if self.max_bans_per_etld1 is None or psl is None:
            return 0
        counts: dict[str, int] = {}
        for content in self._rules.values():
            if not content:
                continue
            rule_entity = content.get("entity")
            if not isinstance(rule_entity, str) or not rule_entity:
                continue
            if "*" in rule_entity or "?" in rule_entity:
                continue
            if content.get("recommendation") != self.recommendation:
                continue
            if is_ip_literal(rule_entity):
                continue
            bucket, _ = psl.etld1(rule_entity)
            counts[bucket] = counts.get(bucket, 0) + 1
        return sum(1 for c in counts.values() if c >= self.max_bans_per_etld1)

    async def _domain_has_ban(self, domain: str) -> bool:
        """True if any scan target sharing this portless domain currently
        resolves to `ban` under the live decision map. Backs the unban guard.

        No per-target hold check is needed here: the hold-list is keyed on the
        portless domain, and reconcile() returns before the guard if the domain
        is held -- so by the time we reach here the domain is not held and
        neither is any of its targets."""
        for _target, status in await self._domain_statuses(domain):
            if self.decide(status) == "ban":
                return True
        return False

    async def _write(self, state_key: str, content: dict[str, Any]) -> None:
        async with self._write_lock:
            loop = asyncio.get_running_loop()
            # throttle bounds state-event floods into the policy room; a config
            # change or big import could otherwise burst.
            if self._min_interval:
                wait = self._min_interval - (loop.time() - self._last_write)
                if wait > 0:
                    await asyncio.sleep(wait)
            # Bounded retry loop for HTTP 429 / M_LIMIT_EXCEEDED only. Every
            # other MatrixRequestError still fails fast (one attempt) exactly as
            # before. On 429 we honor the server's retry_after_ms hint when it
            # survives in the error message, else exponential backoff; both are
            # clamped to _RL_MAX_BACKOFF. On exhaustion we fall through to the
            # original policy_write_failed behavior: log + return WITHOUT
            # touching self._rules, so the next rescan re-derives the write.
            #
            # `sent` + the finally clause replace what used to be bare returns
            # out of the except arms. The throttle clock has to advance on EVERY
            # attempt, not just successful ones: with the old shape a failed
            # write left _last_write at its previous value, so the write that
            # followed a failure computed its wait against a stale timestamp and
            # skipped the throttle entirely -- i.e. an error burst was also the
            # one situation where the rate limit stopped applying.
            attempt = 0
            sent = False
            try:
                while True:
                    try:
                        await self.client.send_state_event(
                            self.room_id, POLICY_RULE_SERVER, content,
                            state_key=state_key,
                        )
                        sent = True
                        break
                    except MLimitExceeded as e:
                        if attempt >= _RL_MAX_RETRIES:
                            self.log.error(
                                "policy write failed: rate limited, retries exhausted",
                                extra={"csreg_alarm": "policy_write_rate_limited",
                                       "state_key": state_key,
                                       "attempts": attempt + 1, "error": str(e)},
                            )
                            break
                        delay = _retry_after_seconds(e, attempt)
                        self.log.warning(
                            "policy write rate limited; backing off",
                            extra={"csreg_alarm": "policy_write_backoff",
                                   "state_key": state_key, "attempt": attempt + 1,
                                   "delay_seconds": round(delay, 3)},
                        )
                        await asyncio.sleep(delay)
                        attempt += 1
                        continue
                    except MatrixRequestError as e:
                        self.log.error(
                            "policy write failed",
                            extra={"csreg_alarm": "policy_write_failed",
                                   "state_key": state_key, "error": str(e)},
                        )
                        break
            finally:
                self._last_write = loop.time()
            if not sent:
                # Fold untouched, so the next rescan re-derives the write.
                return
            self._rules[state_key] = content
            self.log.info(
                "policy %s", "removed" if not content else "added",
                extra={"state_key": state_key, "entity": content.get("entity")},
            )


def _retry_after_seconds(exc: MLimitExceeded, attempt: int) -> float:
    """Best-effort delay for a 429."""
    text = getattr(exc, "message", None) or str(exc)
    # Some homeservers nest the body; also try a JSON parse for retry_after_ms.
    hint_ms: int | None = None
    m = _RETRY_AFTER_RE.search(text)
    if m:
        hint_ms = int(m.group(1))
    else:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and isinstance(obj.get("retry_after_ms"), int):
                hint_ms = obj["retry_after_ms"]
        except (ValueError, TypeError):
            pass

    if hint_ms is not None:
        delay = hint_ms / 1000.0
    else:
        delay = _RL_BASE_BACKOFF * (2 ** attempt)
    if delay < 0:
        delay = 0.0
    return min(delay, _RL_MAX_BACKOFF)


def _as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "serialize"):
        try:
            ser = obj.serialize()
            if isinstance(ser, dict):
                return ser
        except Exception:  # noqa: BLE001
            pass
    try:
        return dict(obj)
    except Exception:  # noqa: BLE001
        return {}
    