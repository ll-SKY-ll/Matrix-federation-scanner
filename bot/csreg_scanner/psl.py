"""Public Suffix List lookup: collapse a host to its eTLD+1 (registrable domain)
so the per-eTLD+1 ban cap can group all subdomains of one controlling entity
into a single budget.

Hand-rolled (no dependency): the algorithm is a small, stable, documented spec
(https://publicsuffix.org/list/) and the data file must be vendored regardless.
Both the ICANN and PRIVATE sections are used, so e.g. evil.co.uk and
evil.dedyn.io are each their own registrable unit.

A stale list does NOT fail uniformly safe, which is why min_psl_version exists.
Additions to the PRIVATE section that we lack collapse siblings into one bucket,
so the cap fills sooner -- over-conservative, harmless. But upstream REMOVALS
invert that (we keep splitting what is now one registrable unit, so the cap is
more permissive), and a newly delegated TLD hits the unknown-TLD fail-safe where
every host becomes its own bucket and the cap is effectively bypassed for it.
Because every scanner evaluates the cap independently against one shared list,
the cap is only as strong as the most permissive participant: a single bot on an
old ICANN section is not outvoted, it just writes the bans the others declined.
Hence the version floor is a HALT, not a warning (see policy._apply_auto_config).

Three sources, freshest VERSION wins: an online fetch, a DB-cached copy of a
previous fetch, and the vendored copy as the floor. The vendored copy is what
makes an outage survivable, so it must never be removed even once fetching
works.

Matrix server names are ASCII per the spec grammar, so a host already arrives in
punycode; we normalise the PSL's own Unicode rules to punycode at load instead.
"""

from __future__ import annotations

import logging
import os
import pkgutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_PSL_RESOURCE = "public_suffix_list.dat"

# The list's own canonical source. Its header asks to be pulled from here and
# only here ("Pulling from any other URL is not guaranteed to be supported"), so
# this is deliberately not configurable.
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# The publishing pipeline stamps both of these into the header. Their PRESENCE is
# itself a validation signal: an HTML error page, a truncated body or a random
# mirror will not have them.
_VERSION_PREFIX = "// VERSION:"
_COMMIT_PREFIX = "// COMMIT:"
_VERSION_FORMAT = "%Y-%m-%d_%H-%M-%S_UTC"

# --- adoption gauntlet -------------------------------------------------------
# A bad list is worse than an old one, so a fetched body must clear all of these
# before it can replace a working list.
_MAX_FETCH_BYTES = 4 * 1024 * 1024      # real list is ~325 KiB
_SECTION_MARKERS = ("// ===BEGIN ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===")
# Sentinels covering all three rule kinds plus one PRIVATE-section entry: a
# truncated or section-filtered body fails at least one of these.
_SENTINELS: tuple[tuple[str, str], ...] = (
    ("example.com", "example.com"),           # normal, ICANN
    ("a.b.example.co.uk", "example.co.uk"),   # multi-label normal
    ("b.test.ck", "b.test.ck"),               # wildcard *.ck
    # Exception !www.ck. NOTE the three labels: "www.ck" is useless as a sentinel
    # because *.ck alone already resolves it to "www.ck", so it passes whether or
    # not the exception rule survived. "www.www.ck" is the case the official PSL
    # vectors use precisely because the two disagree: "www.ck" with the exception,
    # "www.www.ck" without it.
    ("www.www.ck", "www.ck"),
    ("foo.github.io", "foo.github.io"),        # PRIVATE section
)


class PSLValidationError(ValueError):
    """A fetched body is not a usable public suffix list."""


def parse_psl_version(raw: object) -> datetime:
    """Parse a PSL VERSION stamp into an aware datetime.

    Deliberately PARSED rather than string-compared. Lexical ordering happens to
    agree with chronological ordering for every stamp the current pipeline emits,
    but only because the fields are zero-padded -- if upstream ever emitted
    `2026-07-25_9-20-03_UTC`, a lexical `<` would report 9am as LATER than 2pm
    and the floor would silently invert on whichever bot saw it.

    Tolerant of a pasted header line, since the operator's workflow is copy-paste
    straight out of the .dat: all of "2026-07-25_14-20-03_UTC",
    "// VERSION: 2026-07-25_14-20-03_UTC" and "VERSION: <stamp>" are accepted,
    with surrounding whitespace ignored.

    Raises ValueError on anything else -- including a YAML-bare value that
    arrives as an int or bool -- so a typo in min_psl_version is caught at
    config-apply time instead of comparing wrong.
    """
    s = str(raw).strip()
    if s.startswith("//"):
        s = s.lstrip("/").strip()
    if s.upper().startswith("VERSION:"):
        s = s.split(":", 1)[1].strip()
    return datetime.strptime(s, _VERSION_FORMAT).replace(tzinfo=timezone.utc)


def _encode_label(label: str) -> str:
    try:
        label.encode("ascii")
        return label.lower()
    except UnicodeEncodeError:
        return label.encode("idna").decode("ascii").lower()


def _encode_rule(rule: str) -> str:
    return ".".join(_encode_label(lbl) for lbl in rule.split("."))


class PublicSuffixList:
    """Parsed PSL. Rule kinds: normal (com, co.uk), wildcard (*.ck -> any single
    label in that position), exception (!www.ck -> overrides a wildcard). An
    exception wins; otherwise the longest matching rule wins."""

    def __init__(self, rules_text: str, *, source: str = "unknown") -> None:
        self.source = source
        # Kept so an ADOPTED list can be written to the cache blob verbatim.
        # ~325 KiB on top of ~1.2 MiB of parsed sets; re-serialising the rules
        # instead would not round-trip (comments, section markers and the header
        # stamps are all dropped by the parser, and the stamps are exactly what
        # the floor compares against).
        self.raw_text = rules_text
        self.version_raw: str | None = None
        self.version: datetime | None = None
        self.commit: str | None = None
        self._normal: set[str] = set()
        self._wildcard: set[str] = set()   # stored without the leading '*.'
        self._exception: set[str] = set()  # stored without the leading '!'
        # Every TLD the list knows in ANY form, precomputed at load: the
        # rightmost label of every rule. Membership in this set is exactly the
        # old _tld_known() predicate (a bare `tld` rule contributes itself; a
        # `co.uk` rule contributes `uk`), but O(1) instead of three linear
        # endswith scans over ~10k rules on every unknown-TLD miss.
        self._tlds: set[str] = set()
        # No eTLD+1 memo. There used to be one; it was removed when refresh made
        # instances mutable-in-practice. It bought 1.36ms -> 0.13ms per metrics
        # scrape at 500 rule entities (uncached etld1 is 3.3us), which is not
        # worth a size cap, a clear-on-overflow branch and an invalidation
        # question. Without it, a refresh is "build a new PublicSuffixList and
        # swap one reference" -- atomic under asyncio, nothing to invalidate,
        # and the old instance is simply collected.
        self._load(rules_text)

    def _load(self, text: str) -> None:
        self._read_header(text)
        # Keep BOTH sections: comment lines (incl. the ===BEGIN...=== markers)
        # are skipped, so parsing never stops at PRIVATE. Do not filter by
        # section -- doing so silently yields ICANN-only behaviour.
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            rule = _encode_rule(line.split()[0])
            if rule.startswith("!"):
                self._exception.add(rule[1:])
            elif rule.startswith("*."):
                self._wildcard.add(rule[2:])
            else:
                self._normal.add(rule)
            self._tlds.add(rule.lstrip("!").rsplit(".", 1)[-1])

    def _read_header(self, text: str) -> None:
        """Pull VERSION/COMMIT out of the header comments.

        Both are optional HERE and enforced by validate_psl_text() instead: a
        list with no VERSION cannot be ordered against the floor, so it may be
        parsed but must never be ADOPTED. Only the first ~40 lines are scanned;
        the stamps sit in the first 10 and the body contains unrelated lines that
        would otherwise have to be excluded.
        """
        for line in text.splitlines()[:40]:
            if line.startswith(_VERSION_PREFIX) and self.version_raw is None:
                self.version_raw = line[len(_VERSION_PREFIX):].strip()
                try:
                    self.version = parse_psl_version(self.version_raw)
                except ValueError:
                    self.version = None
            elif line.startswith(_COMMIT_PREFIX) and self.commit is None:
                self.commit = line[len(_COMMIT_PREFIX):].strip() or None

    @property
    def rule_count(self) -> int:
        return len(self._normal) + len(self._wildcard) + len(self._exception)

    def describe(self) -> str:
        return (f"{self.version_raw or 'no-version'} "
                f"({self.rule_count} rules, from {self.source})")

    def public_suffix(self, host: str) -> str | None:
        """Public suffix of `host`, or None if its TLD is entirely unknown.

        Per the PSL algorithm: an exception match wins (suffix = the exception
        rule minus its leftmost label); otherwise the longest normal/wildcard
        match wins; if nothing matches at all, the prevailing rule is '*', i.e.
        the rightmost label is itself the suffix -- BUT only when that label is a
        known TLD. A wholly unknown TLD returns None so the caller can fail safe.
        """
        labels = host.split(".")
        n = len(labels)

        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self._exception:
                return ".".join(labels[i + 1:]) or None

        for i in range(n):
            candidate = ".".join(labels[i:])
            if candidate in self._normal:
                return candidate
            parent = ".".join(labels[i + 1:])
            if parent and parent in self._wildcard:
                return candidate

        # No rule matched. The implicit '*' rule makes the rightmost label a
        # suffix, but only if that TLD is known to the list in some form (a
        # normal TLD, a wildcard base, or the base of a longer rule). If the TLD
        # is not in the list at all, it is genuinely unknown -> None.
        tld = labels[-1]
        if self._tld_known(tld):
            return tld
        return None

    def _tld_known(self, tld: str) -> bool:
        return tld in self._tlds

    def etld1(self, host: str) -> tuple[str, bool]:
        """Collapse `host` to its registrable domain (eTLD+1).

        Returns (bucket, matched). matched=False is the fail-safe path for a
        wholly unknown TLD: the whole host becomes its own bucket -- counted, but
        not grouped with siblings -- and the caller emits the psl_unknown_tld
        tripwire. Assumes `host` is a portless, valid Matrix server name; IP
        literals must be filtered by the caller (they have no eTLD+1).
        """
        host = host.strip(".").lower()
        suffix = self.public_suffix(host)
        if suffix is None:
            return host, False
        if host == suffix:
            # host IS a public suffix (e.g. a bare 'co.uk'): no registrable label
            # below it. Not a real ban-rule entity, but handled for totality.
            return host, True
        suffix_labels = suffix.count(".") + 1
        return ".".join(host.split(".")[-(suffix_labels + 1):]), True


def validate_psl_text(text: str, *, source: str) -> PublicSuffixList:
    """Parse `text` and refuse it unless it is credibly a public suffix list.

    A bad list is worse than an old one: adopting a truncated or section-filtered
    body silently changes bucketing for every entity, whereas keeping the previous
    list changes nothing. So this is a gate, not a warning -- callers keep what
    they have when it raises.

    Checks, cheapest first:
      * both section markers present -- catches an ICANN-only or truncated body
      * VERSION present AND parseable -- unorderable against the floor is
        unusable by definition, and its presence rules out an error page
      * sentinel lookups across all three rule kinds plus one PRIVATE entry --
        the check that verifies the parse actually WORKS rather than that the
        bytes look plausible, and (since the list is only ever fetched from the
        canonical source over TLS) the load-bearing catch for a body that is
        structurally present but substantively broken

    Size is capped by the caller during streaming, before this is reached.
    """
    for marker in _SECTION_MARKERS:
        if marker not in text:
            raise PSLValidationError(f"missing section marker {marker!r}")
    psl = PublicSuffixList(text, source=source)
    if psl.version_raw is None:
        raise PSLValidationError("no VERSION stamp in header")
    if psl.version is None:
        raise PSLValidationError(f"unparseable VERSION {psl.version_raw!r}")
    for host, expected in _SENTINELS:
        got, matched = psl.etld1(host)
        if not matched or got != expected:
            raise PSLValidationError(
                f"sentinel {host} resolved to {got!r} (matched={matched}), "
                f"expected {expected!r}"
            )
    return psl


def load_vendored_psl(path: Path | None = None) -> PublicSuffixList:
    """Parse the vendored copy. This is the floor, and it must always work.

    Read via the module loader / pkgutil, NOT Path(__file__).read_text(). maubot
    loads an uploaded plugin straight out of the .mbp with zipimport, so __file__
    is "/.../cs_openreg.mbp/csreg_scanner/psl.py" -- a path whose parent is a
    FILE. read_text() on a sibling of that raises NotADirectoryError [Errno 20],
    which (since this ran from PolicyManager.__init__) took the whole plugin down
    at start(). See _read_resource for the fallback chain.

    NOT validated through validate_psl_text: the vendored file ships with the
    package, so if it is broken that is a build error to fix, not a runtime
    condition to degrade around -- and running the gauntlet here would mean a
    stale vendored copy could leave a bot with no list at all rather than an old
    one. Raises RuntimeError if the resource cannot be read; the caller decides
    what that means (PolicyManager halts only if a cap is configured).
    """
    if path is not None:
        text = path.read_text(encoding="utf-8")
        source = str(path)
    else:
        data, source = _read_resource()
        text = data.decode("utf-8")
    psl = PublicSuffixList(text, source=f"vendored ({source})")
    log.info("loaded vendored public suffix list: %s", psl.describe())
    return psl


class PSLHolder:
    """Mutable holder for the active list, so a refresh is a reference swap.

    Everything that looks up a suffix goes through .current. Replacing it is a
    single attribute assignment with no await in between, so under asyncio no
    reader can observe a half-swapped list -- which is the whole reason the
    parsed rules stay in memory rather than in a table, where a mid-swap read
    would need a version column and a transaction to be safe.

    adopt() enforces MONOTONICITY: a list older than the one in use is refused.
    That is what makes a downgrade -- a stale mirror, a rolled-back publish, a
    replayed cached blob -- unable to walk the fleet backwards past the floor.

    `current` may be None, meaning no list is available at all. That state has to
    be REPRESENTABLE rather than an absent holder: with no list the bot must still
    start (it halts only if a cap is configured), and the refresh task must still
    be able to adopt one -- which it cannot do through a `None` holder.
    """

    def __init__(self, initial: PublicSuffixList | None = None) -> None:
        self.current = initial

    @property
    def version(self) -> datetime | None:
        return self.current.version if self.current is not None else None

    @property
    def version_raw(self) -> str | None:
        return self.current.version_raw if self.current is not None else None

    def describe(self) -> str:
        return self.current.describe() if self.current is not None else "no list"

    def adopt(self, candidate: PublicSuffixList) -> bool:
        """Swap in `candidate` if it is strictly newer. Returns whether it was.

        With no current list there is no predecessor to be newer than, so any
        versioned candidate is adopted: monotonicity constrains REPLACEMENT, and
        going from nothing to something cannot be a downgrade.
        """
        new = candidate.version
        if new is None:
            return False
        cur = self.current.version if self.current is not None else None
        if cur is not None and new <= cur:
            return False
        previous = self.describe()
        self.current = candidate
        log.info("adopted public suffix list %s (was %s)",
                 candidate.describe(), previous)
        return True


def _read_resource() -> tuple[bytes, str]:
    """Read the vendored PSL through whichever mechanism the environment offers.

    Tried in order, because each one fails in a DIFFERENT environment:

      1. ``__loader__.get_data``  -- the module's own loader. Works under
         zipimport (zipimporter.get_data takes exactly this archive-prefixed
         path) AND for a normal file import (SourceFileLoader.get_data just
         opens the file). Depends on nothing but this module already being
         imported, which it necessarily is.
      2. ``pkgutil.get_data``     -- the conventional route, but it resolves the
         PACKAGE by name via find_spec, so it raises ValueError when the package
         object has no __spec__ (e.g. a synthesised placeholder module, as the
         CLI builds to avoid importing maubot).
      3. ``Path(__file__)``       -- plain filesystem read. The only one that
         works when the plugin is running from an unpacked directory and the
         package metadata is unusual, and the only one that CANNOT work from
         inside a .mbp (its parent is a file, so it raises NotADirectoryError).

    Raises RuntimeError if all three come up empty, which is a genuine
    packaging error (missing extra_files entry).
    """
    loader = globals().get("__loader__")
    if loader is not None and hasattr(loader, "get_data"):
        try:
            data = loader.get_data(
                os.path.join(os.path.dirname(__file__), _PSL_RESOURCE)
            )
            if data:
                return data, f"module loader ({type(loader).__name__})"
        except (OSError, ValueError):
            pass
    try:
        data = pkgutil.get_data(__package__ or "csreg_scanner", _PSL_RESOURCE)
        if data:
            return data, f"package resource {_PSL_RESOURCE}"
    except (OSError, ValueError):
        pass
    try:
        return (
            Path(__file__).with_name(_PSL_RESOURCE).read_bytes(),
            f"file {_PSL_RESOURCE}",
        )
    except OSError:
        pass
    raise RuntimeError(
        f"{_PSL_RESOURCE} could not be read from the package "
        "(check the extra_files entry in maubot.yaml)"
    )
