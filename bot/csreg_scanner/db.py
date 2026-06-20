"""Database layer.

Two tables in maubot's managed plugin DB:

  scan_queue  -- distinct pending scan targets (UNIQUE(scan_target)); append-only
                 by sources, drained by the scanner. A row is leased while a scan
                 is in flight (see `leased_until`) and deleted on scan completion
                 (success OR failure -- the terminal write to `scanned` is the
                 anti-wedge record).
  scanned     -- authoritative source of truth; one row per SCAN TARGET (full
                 server-name *with* port). `matrix.org` and `matrix.org:8448` are
                 distinct rows: they can have genuinely different registration
                 behaviour, so dedup/storage is keyed on the full target. The
                 portless `domain` is stored alongside (indexed) for the cross-
                 target unban guard.

SQL is written with $N placeholders and ON CONFLICT, which mautrix's async_db
runs on both SQLite and Postgres backends. Times are wall-clock epoch seconds.

Vocabulary note: a "scan target" is the full Matrix server-name as fed to the
scanner, optionally bearing a port (matrix.org, matrix.org:8448, [::1]:8448).
The "domain" is the same name with the port stripped (util.strip_port) and is
what policy rules are keyed on -- so storage granularity (target) is finer than
policy granularity (domain).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from mautrix.util.async_db import Connection, Database, Scheme, UpgradeTable

from .util import strip_port

upgrade_table = UpgradeTable()


@dataclass(frozen=True)
class ScanRecord:
    """What record_scan reports back about the terminal write, so the caller can
    log a reg-status transition without re-querying.

    ``changed`` is True when the stored reg_status moved to a different value
    this write -- INCLUDING the first-ever scan of a target (no prior row), which
    is a transition from "nothing known" to a status and is treated as a change.
    ``previous_status`` is the prior reg_status, or None on that first-ever scan.

    Note ``changed`` tracks the reg_status only -- federation version changes do
    NOT set it (logging level is driven by reg-status transitions alone). It also
    reflects the STORED status: on a task-failure the stored status is preserved
    (not overwritten to unknown), so a failed scan does not count as a change.
    """

    changed: bool
    previous_status: str | None

# SQLite chunk size for the multi-row VALUES batch in enqueue. One bound
# parameter per target, so this must stay well under SQLITE_MAX_VARIABLE_NUMBER
# (999 on older builds, 32766 on newer ones) -- 500 is safe everywhere and
# already collapses a 40k import from 40k statement dispatches to ~80.
_SQLITE_ENQUEUE_CHUNK = 500


@upgrade_table.register(description="Initial schema: scan_queue + scanned (scan_target keyed)")
async def upgrade_v1(conn: Connection) -> None:
    # scan_queue: one row per pending scan target. `leased_until` is a soft lease
    # (epoch seconds) claimed when a tick launches the scan, so overlapping ticks
    # can't double-launch the same in-flight target. The row is deleted on scan
    # completion; the lease only matters for the crash/cancel case where the
    # terminal write never ran (then the lease expires and the row is reclaimed).
    await conn.execute(
        """
        CREATE TABLE scan_queue (
            scan_target  TEXT PRIMARY KEY,
            leased_until BIGINT
        )
        """
    )
    await conn.execute(
        """
        CREATE TABLE scanned (
            scan_target     TEXT PRIMARY KEY,  -- full name, with port if any
            domain          TEXT NOT NULL,     -- portless; what policy keys on
            discovered_at   BIGINT NOT NULL,   -- immutable, set once on first insert
            last_scan_at    BIGINT NOT NULL,   -- moving; every attempt
            last_success_at BIGINT,            -- only clean scans; NULL = never succeeded
            reg_status      TEXT   NOT NULL,   -- internal status vocabulary
            scan_count      BIGINT NOT NULL DEFAULT 0,
            error_streak    BIGINT NOT NULL DEFAULT 0,
            status_since    BIGINT NOT NULL    -- when reg_status last changed
        )
        """
    )
    # most_overdue orders by staleness RATIO, not raw last_scan_at, so this
    # scalar index can't satisfy its ORDER BY -- it is unused and superseded by
    # upgrade_v2, which drops it. Left here as the historical record of what v1
    # did; do NOT delete this line (migrations are append-only).
    await conn.execute("CREATE INDEX scanned_last_scan_idx ON scanned (last_scan_at)")
    # The unban guard fetches every target sharing a portless domain.
    await conn.execute("CREATE INDEX scanned_domain_idx ON scanned (domain)")


@upgrade_table.register(
    description="Drop unused scanned_last_scan_idx; enable HOT updates on scanned (PG)"
)
async def upgrade_v2(conn: Connection) -> None:
    """Remove `scanned_last_scan_idx` and (on Postgres) give `scanned` heap-page
    headroom so rescans can take the HOT-update path.

    Why: `most_overdue` orders by the computed staleness ratio
    ((now - last_scan_at) / per-status T), which a scalar btree on last_scan_at
    cannot satisfy -- verified via EXPLAIN (Seq Scan + top-N heapsort) and
    pg_stat_user_indexes (idx_scan = 0). The index was never read, but EVERY
    rescan changes last_scan_at, so the index forced every one of ~40k
    continuously-rescanned rows to a non-HOT update: an extra index entry, extra
    WAL, and extra autovacuum on the index, for zero read benefit. Dropping it
    is strictly positive: the one consumer was already a seq scan + sort
    (single-digit ms on 40k rows, on a slow clock).

    IF EXISTS so this is safe whether the index is present (normal forward path
    from v1) or was already dropped manually during diagnosis.

    fillfactor is Postgres-only (HOT is a PG heap optimization; SQLite has no
    such concept and no ALTER TABLE ... SET), so it is branched on conn.scheme.
    Setting fillfactor only affects pages written AFTER this point; existing
    rows get headroom on their next update or a one-time rewrite.
    """
    await conn.execute("DROP INDEX IF EXISTS scanned_last_scan_idx")
    if conn.scheme != Scheme.SQLITE:
        # Postgres/Cockroach: leave ~10% free space per heap page so updates
        # that don't change an indexed column can stay on-page (HOT). domain is
        # still indexed but never changes on rescan, so it won't block HOT;
        # last_scan_at / scan_count are now unindexed, which is the whole point.
        await conn.execute("ALTER TABLE scanned SET (fillfactor = 90)")


@upgrade_table.register(
    description="Add federation version columns (fed_name, fed_version, fed_version_at)"
)
async def upgrade_v3(conn: Connection) -> None:
    """Add the federation /version probe result to each scanned row.

    Three nullable columns, all NULL until a probe records something:
      fed_name        -- advertised server.name (e.g. "Synapse"), 60-char capped
      fed_version     -- advertised server.version (e.g. "1.96.0"), 60-char capped
      fed_version_at  -- epoch seconds of the last AUTHORITATIVE probe (a 200 whose
                         body carried both server.name and server.version keys),
                         independent of whether those values were null. NULL until
                         the first authoritative answer.

    Backfill: existing rows stay NULL and are simply absent from the version
    metric until their next scan populates them -- no migration-time probing.
    """
    await conn.execute("ALTER TABLE scanned ADD COLUMN fed_name TEXT")
    await conn.execute("ALTER TABLE scanned ADD COLUMN fed_version TEXT")
    await conn.execute("ALTER TABLE scanned ADD COLUMN fed_version_at BIGINT")


def now() -> int:
    return int(time.time())


class DB:
    """Thin async wrapper around the maubot-managed Database."""

    def __init__(self, database: Database) -> None:
        self._db = database

    # --- ingress -------------------------------------------------------------

    async def enqueue(self, targets: list[str]) -> None:
        """Add scan targets to the queue, skipping any already in the scanned
        table (dedup authority) and any already queued (UNIQUE backstop). Dedup
        is on the full scan_target -- `matrix.org` and `matrix.org:8448` are
        independent. Sources only ever add; only the scanner drains.

        Set-based, not per-row. A full source fetch is tens of thousands of
        names re-handed every poll, almost all already known, so the old
        one-INSERT-per-target loop paid ~40k statement dispatches (and, on PG,
        40k correlated NOT EXISTS subqueries) on every single poll -- that was
        the CPU spike. Both backends now batch the membership test into one (PG)
        or a handful (SQLite) of planned statements:

          * Postgres/Cockroach: a single INSERT...SELECT over unnest($1::text[])
            with a set anti-join against `scanned`. One round-trip, one plan,
            hash anti-join instead of N index probes.
          * SQLite: chunked multi-row VALUES (no array type), so 40k rows become
            ~80 executes instead of 40k. The NOT EXISTS is still a per-row PK
            probe, but the dominant cost -- statement dispatch across the async
            wrapper -- collapses.

        No return value: the per-poll "newly added" count is not used anywhere
        (total domain count comes from the scanned table via metrics).
        """
        if not targets:
            return
        # De-dupe within the batch first: a single source fetch can contain the
        # same name twice, and on SQLite a duplicate inside one VALUES chunk
        # would otherwise just lean on ON CONFLICT -- cheaper to drop it here.
        # dict.fromkeys preserves order (deterministic logs/tests) while unique.
        unique = list(dict.fromkeys(targets))

        async with self._db.acquire() as conn:
            async with conn.transaction():
                if self._db.scheme == Scheme.SQLITE:
                    await self._enqueue_sqlite(conn, unique)
                else:
                    await self._enqueue_unnest(conn, unique)

    async def _enqueue_unnest(self, conn: Connection, targets: list[str]) -> None:
        """Postgres/Cockroach path: one set-based INSERT for the whole batch.
        `unnest` turns the array into rows; the NOT EXISTS becomes a single hash
        anti-join against `scanned`, and ON CONFLICT covers anything already
        queued. Freshly-inserted rows have leased_until NULL so the next tick
        claims them.
        """
        await conn.execute(
            """
            INSERT INTO scan_queue (scan_target, leased_until)
            SELECT t, NULL
            FROM unnest($1::text[]) AS t
            WHERE NOT EXISTS (
                SELECT 1 FROM scanned s WHERE s.scan_target = t
            )
            ON CONFLICT (scan_target) DO NOTHING
            """,
            targets,
        )

    async def _enqueue_sqlite(self, conn: Connection, targets: list[str]) -> None:
        """SQLite path: SQLite has no array type, so batch with chunked multi-row
        VALUES instead. Each chunk is one prepared statement carrying up to
        _SQLITE_ENQUEUE_CHUNK targets; the anti-join against `scanned` and the
        ON CONFLICT backstop are identical in shape to the PG path, just per-row
        PK probes rather than a single hash anti-join.
        """
        for start in range(0, len(targets), _SQLITE_ENQUEUE_CHUNK):
            chunk = targets[start : start + _SQLITE_ENQUEUE_CHUNK]
            # Build "($1),($2),...,($k)" for this chunk's width. Placeholders are
            # generated from the chunk length only -- never from the values --
            # so this is not an injection surface; the names bind as parameters.
            placeholders = ",".join(f"(${i + 1})" for i in range(len(chunk)))
            # SQLite does not support the parenthesized column-list alias
            # `AS v(t)` on a VALUES clause (that '(' is what raises
            # `near "(": syntax error`). SQLite auto-names VALUES columns
            # column1, column2, ...; reference the first as v.column1 and use a
            # bare table alias.
            await conn.execute(
                f"""
                INSERT INTO scan_queue (scan_target, leased_until)
                SELECT v.column1, NULL
                FROM (VALUES {placeholders}) AS v
                WHERE NOT EXISTS (
                    SELECT 1 FROM scanned s WHERE s.scan_target = v.column1
                )
                ON CONFLICT (scan_target) DO NOTHING
                """,
                *chunk,
            )

    # --- drain / scheduling --------------------------------------------------

    async def pending(self, limit: int, lease_seconds: int) -> list[str]:
        """Claim up to `limit` unleased (or lease-expired) queue rows and return
        their scan targets. Claiming sets leased_until = now + lease_seconds so
        an overlapping tick won't re-launch a target whose scan is still in
        flight. The lease is released implicitly: the terminal write deletes the
        row on completion (success or failure), and only a crash/cancel leaves
        the row to be reclaimed when the lease expires.

        Two statements in one transaction (SELECT-then-UPDATE) rather than a
        single UPDATE...RETURNING, because aiosqlite has no RETURNING on the
        mautrix async_db surface we target; the transaction keeps the claim
        atomic against another tick on the same event loop.
        """
        ts = now()
        claimed: list[str] = []
        async with self._db.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    """
                    SELECT scan_target FROM scan_queue
                    WHERE leased_until IS NULL OR leased_until < $1
                    ORDER BY scan_target
                    LIMIT $2
                    """,
                    ts,
                    limit,
                )
                claimed = [r["scan_target"] for r in rows]
                if claimed:
                    lease = ts + int(lease_seconds)
                    for target in claimed:
                        await conn.execute(
                            "UPDATE scan_queue SET leased_until = $1 WHERE scan_target = $2",
                            lease,
                            target,
                        )
        return claimed

    async def queue_depth(self) -> int:
        return int(await self._db.fetchval("SELECT COUNT(*) FROM scan_queue"))

    async def most_overdue(self, staleness: dict[str, int], limit: int) -> list[str]:
        """Rescan candidates ranked by staleness RATIO: (now - last_scan_at) / T.
        No overdue gate -- the rate meter in the bot governs how many to take per
        tick, so we always hand back the most-relatively-stale rows and let the
        meter pace them. Ratio (not absolute age) is what lets buckets with very
        different T coexist fairly: a T=1h server at age 1.5h (ratio 1.5)
        outranks a T=10h server at age 8h (ratio 0.8), so neither bucket starves
        the other. T comes from validated int config, so the CASE is built from
        trusted ints.

        Returns scan targets (the rescan re-feeds the full name, with port, to
        the scanner -- same as a fresh scan).

        Division is forced to float (multiply the dividend by 1.0): SQLite would
        otherwise float-divide while Postgres truncates integer/integer to 0,
        collapsing the ordering for every row younger than its T. Keeps the
        module's both-backends contract (see docstring up top).
        """
        default_t = staleness.get("unknown", 86400)
        # Keys are interpolated into SQL literals below. The bot pre-filters them
        # against KNOWN_STATUSES, but guard here too: refuse anything outside a
        # safe charset so this method can never build injectable SQL regardless
        # of how it is called.
        for status in staleness:
            if not status or not status.replace("_", "").isalnum():
                raise ValueError(f"unsafe status key in staleness map: {status!r}")
        cases = "\n".join(
            f"WHEN reg_status = '{status}' THEN {int(t)}"
            for status, t in staleness.items()
        )
        case_expr = f"(CASE {cases} ELSE {int(default_t)} END)"
        ts = now()
        # ratio = (now - last_scan_at) * 1.0 / T  -- *1.0 forces float division.
        ratio_expr = f"(($1 - last_scan_at) * 1.0 / {case_expr})"
        rows = await self._db.fetch(
            f"""
            SELECT scan_target
            FROM scanned
            ORDER BY {ratio_expr} DESC
            LIMIT $2
            """,
            ts,
            limit,
        )
        return [r["scan_target"] for r in rows]

    # --- terminal write path ----------------------------------------------

    async def record_scan(
        self,
        scan_target: str,
        *,
        ok: bool,
        status: str | None,
        fed_observed: bool = False,
        fed_name: str | None = None,
        fed_version: str | None = None,
    ) -> ScanRecord:
        """Terminal guarantee for EVERY scan attempt (success or failure):
        (a) upsert the scanned table, THEN (b) delete the queue row -- as a unit.
        Upsert-then-delete ordering means a crash in the gap leaves the row
        queued (harmless re-scan once its lease expires) rather than lost. A
        throwing/timed-out scan still writes a row (anti-wedge: keeps the target
        in the dedup authority so sources don't re-import it forever).

        Keyed on the full scan_target; the portless `domain` is derived here once
        (strip_port) and stored so the unban guard can group targets by domain.

        Returns a ScanRecord(changed, previous_status) so the caller can log a
        reg-status transition at the right level without a second query. The
        signal is derived from the SAME comparison that drives status_since:
        `changed` is True on a first-ever scan (no prior row) or when the stored
        status actually moves; `previous_status` is the prior reg_status (None on
        first-ever). On a task-failure the stored status is preserved, so
        `changed` is False unless the preserved value differs from itself (it
        can't) -- i.e. failures don't count as changes.

        Federation version columns (fed_name / fed_version / fed_version_at)
        follow an OVERWRITE-vs-PRESERVE rule keyed on `fed_observed`, NOT on
        whether the values are null:

          * fed_observed True (the probe got an AUTHORITATIVE answer: a 200 whose
            body carried both server.name and server.version keys) -> OVERWRITE
            both columns with the reported (already strip+60-capped) values,
            INCLUDING overwriting a prior non-null to NULL when the server
            truthfully reported null, and advance fed_version_at to now.
          * fed_observed False (probe failed/skipped/non-200/unparseable/missing
            a key, or the version step never ran because reg-scan failed or no
            time remained) -> PRESERVE the existing columns untouched (do not
            wipe a previously-captured good version on a transient miss), and
            leave fed_version_at unchanged.

        This is why a plain COALESCE won't do (as it does for last_success_at):
        COALESCE could never overwrite a stored version DOWN to null, which an
        authoritative null-report requires. The CASE on $8 (fed_observed)
        expresses overwrite-incl-null vs preserve on both backends.
        """
        ts = now()
        domain = strip_port(scan_target)
        async with self._db.acquire() as conn:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    "SELECT reg_status, error_streak, status_since "
                    "FROM scanned WHERE scan_target = $1",
                    scan_target,
                )
                if ok:
                    new_status = status or "unknown"
                    last_success = ts
                    streak = 0
                else:
                    # Keep the last known status on failure; only refresh the
                    # attempt clock and bump the failure signal. A first-ever
                    # scan that fails lands as "unknown" (no prior status to
                    # keep). Crucially we do NOT reset a known status to unknown
                    # on a transient failure -- that could flip a ban-mapped row
                    # to unban-eligible.
                    new_status = existing["reg_status"] if existing else "unknown"
                    last_success = None  # COALESCE preserves any prior success
                    streak = (existing["error_streak"] + 1) if existing else 1

                # Change signal + status_since both come from this one comparison.
                # First-ever insert: a transition from "nothing known" -> counts
                # as changed, previous_status None. On a real status move: changed,
                # previous_status is the old value. Unchanged: preserve status_since.
                prev_status = existing["reg_status"] if existing else None
                if existing is None:
                    changed = True
                    status_since = ts
                elif new_status != existing["reg_status"]:
                    changed = True
                    status_since = ts
                else:
                    changed = False
                    status_since = existing["status_since"] or ts

                # Federation version values to feed the INSERT branch. On a
                # brand-new row there is nothing to preserve, so a non-authoritative
                # probe simply inserts NULLs; an authoritative probe inserts the
                # reported values (which may themselves be null). fed_version_at is
                # set only when authoritative. The UPDATE branch (below) re-derives
                # overwrite-vs-preserve from the $8 flag via CASE.
                ins_name = fed_name if fed_observed else None
                ins_version = fed_version if fed_observed else None
                ins_version_at = ts if fed_observed else None

                await conn.execute(
                    """
                    INSERT INTO scanned
                        (scan_target, domain, discovered_at, last_scan_at,
                         last_success_at, reg_status, scan_count, error_streak,
                         status_since, fed_name, fed_version, fed_version_at)
                    VALUES ($1, $2, $3, $3, $4, $5, 1, $6, $7, $9, $10, $11)
                    ON CONFLICT (scan_target) DO UPDATE SET
                        last_scan_at    = excluded.last_scan_at,
                        last_success_at = COALESCE(excluded.last_success_at,
                                                   scanned.last_success_at),
                        reg_status      = excluded.reg_status,
                        scan_count      = scanned.scan_count + 1,
                        error_streak    = excluded.error_streak,
                        status_since    = excluded.status_since,
                        fed_name        = CASE WHEN $8
                                               THEN excluded.fed_name
                                               ELSE scanned.fed_name END,
                        fed_version     = CASE WHEN $8
                                               THEN excluded.fed_version
                                               ELSE scanned.fed_version END,
                        fed_version_at  = CASE WHEN $8
                                               THEN excluded.fed_version_at
                                               ELSE scanned.fed_version_at END
                    """,
                    scan_target,
                    domain,
                    ts,
                    last_success,
                    new_status,
                    streak,
                    status_since,
                    fed_observed,
                    ins_name,
                    ins_version,
                    ins_version_at,
                )
                await conn.execute(
                    "DELETE FROM scan_queue WHERE scan_target = $1", scan_target
                )
        return ScanRecord(changed=changed, previous_status=prev_status)

    async def statuses_for_domain(self, domain: str) -> list[tuple[str, str]]:
        """Every (scan_target, reg_status) recorded for any scan target sharing
        this portless domain. Backs the unban guard: an unban is only
        allowed if NONE of the non-held siblings resolve to `ban` under the live
        decision map -- so `matrix.org` (dangerously_open -> ban) blocks an
        unban triggered by `matrix.org:8888` (closed -> unban). Returns the
        target too (not just the status) so the guard can exclude hold-listed
        targets. Indexed on `domain`."""
        rows = await self._db.fetch(
            "SELECT scan_target, reg_status FROM scanned WHERE domain = $1", domain
        )
        return [(r["scan_target"], r["reg_status"]) for r in rows]

    # --- metrics / counts ----------------------------------------------------

    async def all_statuses(self) -> list[tuple[str, str, int | None]]:
        rows = await self._db.fetch(
            "SELECT scan_target, reg_status, status_since FROM scanned"
        )
        return [(r["scan_target"], r["reg_status"], r["status_since"]) for r in rows]

    async def bucket_counts(self) -> dict[str, int]:
        rows = await self._db.fetch(
            "SELECT reg_status, COUNT(*) AS n FROM scanned GROUP BY reg_status"
        )
        return {r["reg_status"]: int(r["n"]) for r in rows}

    async def fed_version_counts(self) -> list[tuple[str, str, int]]:
        """Server counts grouped by (fed_name, fed_version) pair, for the
        matrix_server_federation_version_count metric. The (name, version)
        analogue of bucket_counts -- a GROUP BY over the whole table on the
        metrics clock, which is why fed_name/fed_version are deliberately
        unindexed (see upgrade_v3).

        Only rows whose fed_name is non-null are counted: a row that has never
        had an authoritative probe (or whose server reported a null name) has no
        place in a name/version distribution. A row with a name but a null
        version is included with an empty-string version, so a server that
        advertises a name but no version is still visible as its own bucket
        rather than silently dropped.

        COALESCE(fed_version, '') keeps the GROUP BY key non-null so the two
        backends agree and the metric renderer always has a string to emit; the
        renderer maps '' to an empty label value, which reads as "name known,
        version not reported".
        """
        rows = await self._db.fetch(
            """
            SELECT fed_name AS name,
                   COALESCE(fed_version, '') AS version,
                   COUNT(*) AS n
            FROM scanned
            WHERE fed_name IS NOT NULL
            GROUP BY fed_name, COALESCE(fed_version, '')
            """
        )
        return [(r["name"], r["version"], int(r["n"])) for r in rows]

    async def total_scans(self) -> int:
        """Cumulative count of every scan execution (incl. rescans), summed from
        the per-target scan_count. Monotonic across restarts since it's derived
        from persisted state -- the right source for a Prometheus counter.
        COALESCE so an empty table yields 0, not NULL."""
        return int(
            await self._db.fetchval("SELECT COALESCE(SUM(scan_count), 0) FROM scanned")
        )