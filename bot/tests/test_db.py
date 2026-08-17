"""Tests for the database layer (csreg_scanner/db.py).

Why this file is the heart of the fail-safe story
--------------------------------------------------
The `scanned` table is the authoritative source of truth. Its `reg_status`
column is what the policy layer reads to decide ban vs unban. So a wrong write
here is not a cosmetic bug -- it can cause a wrong ban or, worse, silently erode
a correct ban. That is why `record_scan` gets the most care.

The single most important behavior, in the code's own words:

    "we do NOT reset a known status to unknown on a transient failure -- that
     could flip a ban-mapped row to unban-eligible."

IMPORTANT DISTINCTION (read before editing):

  `ok` does NOT mean "the remote server answered." Per ScanResult's contract
  AND the actual scan() control flow:
    * ok=True  -> classification returned a status we trust, *including* a
                  deliberate `unknown`. This covers the NORMAL failure modes:
                  a connection refused, DNS failure, timeout, or any network
                  error is caught INSIDE classify() (and the resolver/probe
                  layers), which returns `unknown` -- so scan() takes its
                  success path and reports ok=True, status="unknown". An
                  unreachable server is a real, recorded observation
                  (advances status_since, zeroes error_streak, sets
                  last_success_at).
    * ok=False -> ONLY when an UNEXPECTED exception escaped classify()
                  altogether -- i.e. classify() violated its own never-raises
                  contract (a bug). scan()'s bare `except Exception` is the sole
                  producer of ok=False, and its own comment calls it "defensive;
                  classify shouldn't raise". A normal unreachable/denied/timed-
                  out server does NOT reach here -- it is ok=True/unknown.

  So the string "unknown" in reg_status can arrive two ways, but BOTH are
  ok=True in normal operation:
    (a) reached and deliberately classified unknown, or
    (b) unreachable/denied/timeout -- caught inside classify(), still unknown.
  The ok=False path (below) is the rare defensive case: an unexpected crash in
  classification. The preserve-on-failure behavior it triggers is still worth
  guarding (a crash must not erode a known status either), which is what the
  tests here verify -- they just exercise it via ok=False directly rather than
  by staging an unexpected crash.

All tests use the shared `database` fixture from conftest.py, which parametrizes
over sqlite (always) and postgres (when TEST_POSTGRES_DSN is set). So each test
here is really run once per backend.
"""

from __future__ import annotations

import pytest

from csreg_scanner.db import DB, ScanRecord


# Real status vocabulary (taxonomy.KNOWN_STATUSES). Using real values so a
# vocabulary change surfaces here rather than the tests drifting into fiction.
DANGEROUS = "dangerously_open"
CLOSED = "closed"
OPEN = "open"
UNKNOWN = "unknown"


async def _row(database, scan_target):
    """Read a scanned row back as a dict for assertions.

    Tests assert against the STORED row, not just record_scan's return value, so
    they catch a divergence between what the ScanRecord reports and what actually
    landed in the table.
    """
    r = await database.fetchrow(
        "SELECT reg_status, error_streak, status_since, last_success_at, "
        "scan_count, discovered_at, fed_name, fed_version, fed_version_at "
        "FROM scanned WHERE scan_target = $1",
        scan_target,
    )
    return dict(r) if r is not None else None


# ===========================================================================
# Unit 1: record_scan -- the terminal write contract. The crown jewels.
# ===========================================================================


async def test_record_scan_first_ever_insert_reports_change(database):
    """A brand-new target: inserts a row, reports changed=True, prev=None.

    First-ever classification is a transition from "nothing known" to a status,
    so `changed` is True and `previous_status` is None. scan_count starts at 1.
    """
    db = DB(database)
    rec = await db.record_scan("new.example", ok=True, status=CLOSED)

    assert rec.changed is True
    assert rec.previous_status is None

    row = await _row(database, "new.example")
    assert row["reg_status"] == CLOSED
    assert row["scan_count"] == 1
    assert row["error_streak"] == 0
    assert row["last_success_at"] is not None   # a success stamps this


async def test_record_scan_FAILURE_PRESERVES_KNOWN_STATUS(database):
    """THE ban-erosion guard. The single most important test in the suite.

    A target is first classified dangerously_open (ok=True, a real observation).
    Then a scan fails at the DEFENSIVE level (ok=False -- an unexpected
    exception escaped classify(), NOT a normal unreachable server, which would
    be ok=True/unknown). The stored reg_status MUST stay dangerously_open. If a
    crash mid-classification could reset it to unknown, a downstream unban-guard
    pass might see unknown instead of the real dangerous status and lift a ban
    that should stand -- a transient bug silently eroding a ban.

    Assertions cover the WHOLE preserve contract, not just the status string,
    because (see module docstring) "unknown" is ambiguous and only the full set
    of signals proves this is a preserve and not an accidental reclassification:
      * reg_status stays dangerously_open   (the ban-mapped status survives)
      * error_streak increments             (the failure IS recorded as a failure)
      * last_success_at is preserved        (the prior good scan isn't wiped)
      * changed is False                    (a preserve is not a transition)
    """
    db = DB(database)
    await db.record_scan("evil.example", ok=True, status=DANGEROUS)
    row0 = await _row(database, "evil.example")

    # A transient scan failure: ok=False, no status carried.
    rec = await db.record_scan("evil.example", ok=False, status=None)

    row1 = await _row(database, "evil.example")
    assert row1["reg_status"] == DANGEROUS          # <-- ban NOT eroded
    assert row1["error_streak"] == 1                # failure recorded
    assert row1["last_success_at"] == row0["last_success_at"]  # prior success kept
    assert rec.changed is False                     # preserve != change
    assert rec.previous_status == DANGEROUS


async def test_record_scan_failure_preserves_status_since(database):
    """A run of failures must not reset the status_since clock.

    status_since is when reg_status last actually moved. The stale-entry cleanup
    lane ages entries off this timestamp, so if a failure reset it, an entry
    that went unknown and stays unknown would never age out. Assert two failures
    in a row leave status_since exactly where the last real transition put it.
    """
    db = DB(database)
    await db.record_scan("s.example", ok=True, status=UNKNOWN)
    since = (await _row(database, "s.example"))["status_since"]

    await db.record_scan("s.example", ok=False, status=None)
    await db.record_scan("s.example", ok=False, status=None)

    row = await _row(database, "s.example")
    assert row["status_since"] == since     # clock did not reset
    assert row["error_streak"] == 2         # both failures counted


async def test_record_scan_first_ever_failure_lands_unknown(database):
    """A first-ever scan that hits the DEFENSIVE ok=False path lands unknown.

    ok=False means an unexpected exception escaped classify() (a crash, not a
    normal unreachable server -- that would be ok=True/unknown). On a first-ever
    target there is no prior status to preserve, so the row lands as unknown,
    distinguished from a deliberate ok=True unknown by:
      * error_streak == 1        (a failure was recorded)
      * last_success_at is None  (never succeeded)
    The point of the test is the preserve/insert bookkeeping on the ok=False
    branch, not to claim ok=False is how unreachable servers normally arrive.
    """
    db = DB(database)
    rec = await db.record_scan("neverworked.example", ok=False, status=None)

    row = await _row(database, "neverworked.example")
    assert row["reg_status"] == UNKNOWN
    assert row["error_streak"] == 1
    assert row["last_success_at"] is None   # <-- the tell: never succeeded
    assert rec.changed is True              # nothing-known -> unknown is a move
    assert rec.previous_status is None


async def test_record_scan_deliberate_unknown_is_a_success(database):
    """The FIRST meaning of unknown: reached and deliberately classified unknown.

    ok=True status=unknown is a trusted observation, NOT a failure. It must
    stamp last_success_at and keep error_streak at 0 -- the opposite of the
    first-ever-failure row above, even though both show reg_status == unknown.
    """
    db = DB(database)
    await db.record_scan("reached.example", ok=True, status=UNKNOWN)

    row = await _row(database, "reached.example")
    assert row["reg_status"] == UNKNOWN
    assert row["error_streak"] == 0           # not a failure
    assert row["last_success_at"] is not None  # <-- the tell: it succeeded


async def test_record_scan_success_moves_status_and_flags_change(database):
    """A successful reclassification moves the status and reports the transition.

    Complement to the preserve tests: without this, code that preserved
    EVERYTHING would pass every preserve test while being useless. A real move
    from closed -> dangerously_open must update the row and report changed=True
    with the correct previous_status.
    """
    db = DB(database)
    await db.record_scan("m.example", ok=True, status=CLOSED)
    rec = await db.record_scan("m.example", ok=True, status=DANGEROUS)

    assert rec.changed is True
    assert rec.previous_status == CLOSED
    row = await _row(database, "m.example")
    assert row["reg_status"] == DANGEROUS
    assert row["scan_count"] == 2       # second scan of the same target


async def test_record_scan_same_status_rescan_is_not_a_change(database):
    """Re-scanning to the same status is not a transition.

    changed must be False and status_since preserved when a successful rescan
    lands the same status. This keeps the steady-state rescan firehose out of
    the "changed" signal (which drives INFO-level logging).
    """
    db = DB(database)
    await db.record_scan("q.example", ok=True, status=OPEN)
    since = (await _row(database, "q.example"))["status_since"]
    rec = await db.record_scan("q.example", ok=True, status=OPEN)

    assert rec.changed is False
    row = await _row(database, "q.example")
    assert row["status_since"] == since
    assert row["scan_count"] == 2


async def test_record_scan_deletes_queue_row(database):
    """Upsert-then-delete: the terminal write removes the queue row as a unit.

    Can't inject a mid-transaction crash here, so this asserts the happy-path
    half of the anti-wedge contract: after record_scan, the scanned row exists
    AND the queue row for that target is gone.
    """
    db = DB(database)
    await db.enqueue(["dq.example"])
    assert await db.queue_depth() == 1

    await db.record_scan("dq.example", ok=True, status=CLOSED)

    assert await db.queue_depth() == 0                  # queue row deleted
    assert await _row(database, "dq.example") is not None  # scanned row exists


# --- fed version overwrite-vs-preserve (the CASE on fed_observed) -----------


async def test_fed_version_authoritative_overwrites(database):
    """An authoritative probe overwrites fed_name/fed_version and stamps _at."""
    db = DB(database)
    await db.record_scan(
        "fv.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name="Synapse", fed_version="1.96.0",
    )
    row = await _row(database, "fv.example")
    assert row["fed_name"] == "Synapse"
    assert row["fed_version"] == "1.96.0"
    assert row["fed_version_at"] is not None


async def test_fed_version_nonauthoritative_preserves(database):
    """A NON-authoritative probe must NOT wipe a previously captured version.

    The preserve half of the CASE on fed_observed: a transient probe miss
    (fed_observed=False) leaves the stored version untouched, so a good version
    isn't lost to a blip -- mirroring the reg_status preserve rule.
    """
    db = DB(database)
    await db.record_scan(
        "fv2.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name="Dendrite", fed_version="0.13.0",
    )
    # Next scan: probe not authoritative, carries empty fields.
    await db.record_scan(
        "fv2.example", ok=True, status=CLOSED,
        fed_observed=False, fed_name=None, fed_version=None,
    )
    row = await _row(database, "fv2.example")
    assert row["fed_name"] == "Dendrite"    # preserved, not wiped
    assert row["fed_version"] == "0.13.0"


async def test_fed_version_authoritative_null_report_clears(database):
    """An authoritative NULL report overwrites a prior version DOWN to null.

    This is the case a plain COALESCE could never express (COALESCE can't
    overwrite to null), which is exactly why the code uses a CASE. A server that
    truthfully stops advertising a version (X -> -) must clear the stored value.
    version_changed is deliberately False for a fall-to-null (see ScanRecord).
    """
    db = DB(database)
    await db.record_scan(
        "fv3.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name="Synapse", fed_version="1.96.0",
    )
    rec = await db.record_scan(
        "fv3.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name=None, fed_version=None,
    )
    row = await _row(database, "fv3.example")
    assert row["fed_name"] is None          # cleared by authoritative null
    assert row["fed_version"] is None
    assert rec.version_changed is False     # fall-to-null is not counted


async def test_fed_version_change_signal_on_real_move(database):
    """version_changed is True only on an authoritative non-null version move."""
    db = DB(database)
    await db.record_scan(
        "fv4.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name="Synapse", fed_version="1.96.0",
    )
    rec = await db.record_scan(
        "fv4.example", ok=True, status=CLOSED,
        fed_observed=True, fed_name="Synapse", fed_version="1.97.0",
    )
    assert rec.version_changed is True
    assert rec.previous_version == ("Synapse", "1.96.0")


# ===========================================================================
# Unit 2: most_overdue -- the SQL-injection + divide-by-zero guards.
# ===========================================================================
#
# most_overdue interpolates status keys directly into a CASE expression (they're
# effectively identifiers, not bindable params), so it MUST refuse anything that
# could carry SQL. These are refusal tests -- the most valuable kind here.


async def test_most_overdue_rejects_injectable_status_key(database):
    """A status key with SQL metacharacters must raise, never be interpolated.

    This is the injection guard. If it ever fails to raise, the CASE builder
    would splice attacker/typo text straight into SQL. The guard's whole purpose
    is that the method "can never build injectable SQL regardless of how it is
    called" -- so we prove it refuses.
    """
    db = DB(database)
    with pytest.raises(ValueError):
        await db.most_overdue({"x'; DROP TABLE scanned; --": 3600}, limit=10)


async def test_most_overdue_rejects_nonpositive_T(database):
    """A non-positive staleness T must raise (it would be a divide-by-zero).

    Postgres raises on /0; SQLite silently yields NULL and destroys the
    ordering. Either way the method refuses up front rather than emitting a
    query that misbehaves per-backend.
    """
    db = DB(database)
    with pytest.raises(ValueError):
        await db.most_overdue({UNKNOWN: 0}, limit=10)
    with pytest.raises(ValueError):
        await db.most_overdue({UNKNOWN: -5}, limit=10)


async def test_most_overdue_empty_map_degrades_not_crashes(database):
    """An empty staleness map must degrade to the bare default, not crash.

    An empty CASE ("CASE  ELSE 86400 END") is a syntax error on both backends;
    the docstring records that this once silently killed every rescan tick. So
    an empty map must produce a VALID query. On an empty table it returns [].
    """
    db = DB(database)
    result = await db.most_overdue({}, limit=10)
    assert result == []


async def test_most_overdue_orders_by_staleness_ratio(database):
    """Sanity: with valid input, the most relatively-stale target ranks first.

    Not a fail-safe test, but it proves the query actually runs and orders on
    the ratio rather than raising or returning garbage. Two targets, same age,
    different T -> the one with the smaller T is relatively staler and ranks
    first. (Runs against real SQL on both backends via the fixture.)
    """
    db = DB(database)
    # Both scanned now; give them different statuses so the CASE assigns
    # different T values.
    await db.record_scan("fast.example", ok=True, status=UNKNOWN)
    await db.record_scan("slow.example", ok=True, status=CLOSED)
    # unknown gets a small T (stale fast), closed a large T (stale slow).
    order = await db.most_overdue({UNKNOWN: 60, CLOSED: 86400}, limit=10)
    assert order.index("fast.example") < order.index("slow.example")


# ===========================================================================
# Unit 3: enqueue -- dedup against the scanned authority + batch correctness.
# ===========================================================================


async def test_enqueue_skips_already_scanned(database):
    """A target already in `scanned` (the dedup authority) is not re-queued."""
    db = DB(database)
    await db.record_scan("known.example", ok=True, status=CLOSED)
    await db.enqueue(["known.example", "fresh.example"])

    # Only fresh.example should be pending; known.example is already scanned.
    claimed = await db.pending(limit=10, lease_seconds=60)
    assert "fresh.example" in claimed
    assert "known.example" not in claimed


async def test_enqueue_dedups_within_batch(database):
    """Duplicates inside one batch collapse to a single queue row."""
    db = DB(database)
    await db.enqueue(["dup.example", "dup.example", "dup.example"])
    assert await db.queue_depth() == 1


async def test_enqueue_batch_over_chunk_size(database):
    """A batch larger than the SQLite chunk size still enqueues everything.

    Exercises the chunked multi-row VALUES path (chunk size 500). 1050 targets
    span three chunks; all must land. Guards the chunking boundary logic.
    """
    db = DB(database)
    targets = [f"srv{i}.example" for i in range(1050)]
    await db.enqueue(targets)
    assert await db.queue_depth() == 1050


async def test_enqueue_empty_is_noop(database):
    """Enqueuing nothing does nothing (and doesn't error)."""
    db = DB(database)
    await db.enqueue([])
    assert await db.queue_depth() == 0


# ===========================================================================
# Unit 4: pending -- the lease claim (anti double-launch).
# ===========================================================================


async def test_pending_claims_and_releases_only_after_expiry(database):
    """A claimed row is not re-claimed within its lease, but is after expiry.

    First claim leases the row for a long window -> a second immediate claim
    sees nothing (the anti-double-launch guard). A claim with lease_seconds<=0
    (already expired) reclaims it. This proves the lease actually gates
    re-claiming rather than every tick grabbing the same target.
    """
    db = DB(database)
    await db.enqueue(["lease.example"])

    first = await db.pending(limit=10, lease_seconds=3600)
    assert first == ["lease.example"]

    # Within the lease: nothing claimable.
    second = await db.pending(limit=10, lease_seconds=3600)
    assert second == []

    # Simulate the lease EXPIRING. A test can't wait out a 3600s lease, and
    # re-calling pending() doesn't rewind the already-stored future lease. So
    # force leased_until into the past directly (this is exactly the state a
    # crashed/cancelled scan leaves behind: a stale lease that must be
    # reclaimable). Then a normal claim must pick it back up.
    await database.execute(
        "UPDATE scan_queue SET leased_until = $1 WHERE scan_target = $2",
        1,  # epoch second 1 = far in the past
        "lease.example",
    )
    reclaimed = await db.pending(limit=10, lease_seconds=60)
    assert reclaimed == ["lease.example"]


async def test_pending_respects_limit(database):
    """pending returns at most `limit` targets."""
    db = DB(database)
    await db.enqueue([f"p{i}.example" for i in range(5)])
    claimed = await db.pending(limit=2, lease_seconds=60)
    assert len(claimed) == 2


# ===========================================================================
# Unit 5: read-back methods -- statuses_for_domain (fail-safe) + metrics.
# ===========================================================================


async def test_statuses_for_domain_groups_port_variants(database):
    """statuses_for_domain backs the unban guard -- it must find ALL siblings.

    matrix.example and matrix.example:8448 are distinct scan_targets but share
    the portless domain matrix.example. The unban guard only allows an unban if
    NONE of a domain's siblings is ban-mapped, so this method returning an
    INCOMPLETE set could let a wrong unban through. Assert both port-variants
    come back for the shared domain, with their statuses.
    """
    db = DB(database)
    await db.record_scan("matrix.example", ok=True, status=DANGEROUS)
    await db.record_scan("matrix.example:8448", ok=True, status=CLOSED)

    siblings = await db.statuses_for_domain("matrix.example")
    as_dict = dict(siblings)
    assert as_dict.get("matrix.example") == DANGEROUS
    assert as_dict.get("matrix.example:8448") == CLOSED
    assert len(siblings) == 2   # both siblings present -> guard sees the danger


async def test_bucket_counts_groups_by_status(database):
    """bucket_counts returns per-status row counts (feeds the status gauge)."""
    db = DB(database)
    await db.record_scan("a.example", ok=True, status=CLOSED)
    await db.record_scan("b.example", ok=True, status=CLOSED)
    await db.record_scan("c.example", ok=True, status=DANGEROUS)

    counts = await db.bucket_counts()
    assert counts.get(CLOSED) == 2
    assert counts.get(DANGEROUS) == 1


async def test_scan_totals_splits_initial_and_rescans(database):
    """scan_totals derives (initial, rescans, total) from persisted state.

    One target scanned 3 times + one scanned once = 2 initial scans (one row
    each) and (4 total scan_count - 2 rows) = 2 rescans. Proves the
    first-vs-subsequent accounting the counters rely on.
    """
    db = DB(database)
    await db.record_scan("t1.example", ok=True, status=CLOSED)
    await db.record_scan("t1.example", ok=True, status=CLOSED)
    await db.record_scan("t1.example", ok=True, status=CLOSED)
    await db.record_scan("t2.example", ok=True, status=CLOSED)

    initial, rescans, total = await db.scan_totals()
    assert initial == 2
    assert rescans == 2
    assert total == 4


async def test_psl_cache_round_trip(database):
    """put_cached_psl then get_cached_psl returns the same tuple.

    The cache's SAFETY (monotonicity) lives in psl.py (PSLHolder.adopt); here we
    only prove storage round-trips a row faithfully and that get returns None
    when empty.
    """
    db = DB(database)
    assert await db.get_cached_psl() is None    # empty -> None

    await db.put_cached_psl("2026-07-25_14-20-03_UTC", "abc123", "// body", ts=123)
    got = await db.get_cached_psl()
    assert got == ("2026-07-25_14-20-03_UTC", "abc123", "// body", 123)
