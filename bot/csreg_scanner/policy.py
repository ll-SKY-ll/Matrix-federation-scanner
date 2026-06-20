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
from typing import Any, Protocol

from mautrix.client import Client
from mautrix.errors import MatrixRequestError, MLimitExceeded, MNotFound
from mautrix.types import EventType, RoomID, StateEvent

from .util import is_ip_literal, strip_port, validate_server_name

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
MAX_SUPPORTED_SCHEMA_VERSION = 1

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
    ) -> None:
        self.client = client
        self.room_id = room_id
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
        self.halted: bool = True
        self.halt_reason: str = "auto_config not yet read"
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

        # local fold of policy room state: state_key -> content (empty = removed)
        self._rules: dict[str, dict[str, Any]] = {}

        # write throttle (distinct from scan concurrency)
        self._min_interval = 1.0 / max_writes_per_second if max_writes_per_second else 0
        self._write_lock = asyncio.Lock()
        self._last_write = 0.0

    # --- auto_config ---------------------------------------------------------

    async def refresh_auto_config(self) -> None:
        """Read auto_config from the room ONCE (startup) and validate it. After
        this, the value is kept live by apply_auto_config_event() fired from the
        bot's state-event handler -- so this network read happens at start() and
        on an explicit reload, NOT on every scan/rescan tick"""
        try:
            content = await self.client.get_state_event(
                self.room_id, self.auto_config_type, ""
            )
        except MNotFound:
            self._halt("auto_config state event absent")
            return
        except MatrixRequestError as e:
            self._halt(f"auto_config unreadable: {e}")
            return

        data = _as_dict(content)
        self._apply_auto_config(data)

    def apply_auto_config_event(self, content: Any) -> None:
        """Apply a live auto_config update delivered as a room state event.
        Called from the bot's state-event handler the moment the operator edits
        the event, so governance changes propagate without a redeploy and
        without per-tick polling."""
        self._apply_auto_config(_as_dict(content))

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

        # --- recommendation: fully list-controlled, load-bearing ------------
        # Hashed into every state key, so it MUST be present and a non-empty
        # string before any write. The list is the single source. Absent/empty/non-str
        # => halt (fail-closed: no recommendation, no key derivation, no writes).
        # NOTE: changing this value still orphans every existing rule. That is
        # now an unguarded operator action; it is only protected by the room PL
        # restricting who may write the auto_config event. Don't change it.
        recommendation = data.get("recommendation")
        if not isinstance(recommendation, str) or not recommendation:
            self._halt(
                f"recommendation missing or not a non-empty string: {recommendation!r}"
            )
            return
        self.recommendation = recommendation

        # --- soft fields, validated; universal floor toward hold ------------
        # ban_reason flows into rule content as the human-facing `reason`, so it
        # must be a non-empty string; anything else falls back to the default.
        ban_reason = data.get("ban_reason")
        self.ban_reason = (
            ban_reason if isinstance(ban_reason, str) and ban_reason
            else _DEFAULT_BAN_REASON
        )

        default_action = data.get("default_action", "hold")
        if default_action not in ACTIONS:
            self.log.warning(
                "auto_config default_action invalid; coercing to hold",
                extra={"csreg_alarm": "auto_config_default_action", "value": default_action},
            )
            default_action = "hold"
        self.default_action = default_action

        clean: dict[str, str] = {}
        raw_map = data.get("decision_map") or {}
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
        raw_hold = data.get("hold_targets") or []
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
            data.get("write_policies_for_ip_literals") is True
        )

        if self.halted:
            self.log.info("auto_config valid again; resuming")
        self.halted = False
        self.halt_reason = ""

    def _halt(self, reason: str) -> None:
        if not self.halted or reason != self.halt_reason:
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
        self.halted = True
        self.halt_reason = reason

    # --- decision  -----------------------------------------------------------

    def decide(self, status: str) -> str:
        action = self.decision_map.get(status, self.default_action)
        return action if action in ACTIONS else "hold"

    # --- local state fold -----------------------------------------------------

    async def load_rules(self) -> None:
        """Populate the local rule fold once from current room state, so the
        no-op guard is a local lookup, not a C-S API round-trip per server.
        """
        self._rules.clear()
        try:
            state = await self.client.get_state(self.room_id)
        except MatrixRequestError as e:
            self.log.warning("could not load policy room state: %s", e)
            return
        for evt in state:
            if not isinstance(evt, StateEvent):
                continue
            if str(evt.type) != "m.policy.rule.server":
                continue
            content = _as_dict(evt.content)
            self._rules[evt.state_key] = content

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
            # throttle bounds state-event floods into the policy room; a config
            # change or big import could otherwise burst.
            if self._min_interval:
                loop = asyncio.get_event_loop()
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
            attempt = 0
            while True:
                try:
                    await self.client.send_state_event(
                        self.room_id, POLICY_RULE_SERVER, content, state_key=state_key
                    )
                    break
                except MLimitExceeded as e:
                    if attempt >= _RL_MAX_RETRIES:
                        self.log.error(
                            "policy write failed: rate limited, retries exhausted",
                            extra={"csreg_alarm": "policy_write_rate_limited",
                                   "state_key": state_key,
                                   "attempts": attempt + 1, "error": str(e)},
                        )
                        return
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
                    return
            self._rules[state_key] = content
            self._last_write = asyncio.get_event_loop().time()
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