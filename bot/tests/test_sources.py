"""Tests for ingress sources (csreg_scanner/sources.py).

What's actually being guarded here
-----------------------------------
The PostgresSource lets an operator point the bot at a foreign DB and pull a
column of server names to scan. The security boundary is NOT this file -- it is
(a) a dedicated SELECT-only Postgres ROLE, and (b) a readonly transaction. The
code says so twice, and the tests here are written to RESPECT that: they never
claim `_is_select_only` makes writes impossible.

So the tests split into two honest halves:

  * `_is_select_only` (units 1 & 2): a shape check that fails fast on obviously
    non-SELECT / statement-stacked queries. Tests prove its STATED contract
    (reject stacking, reject non-SELECT) -- and one test deliberately PINS a
    known hole (a data-modifying CTE slips past the shape check) so nobody
    mistakes the regex for the boundary.

  * the readonly transaction (unit 4): the layer that actually stops writes.
    Tested against real Postgres, with a POSITIVE CONTROL first (prove a write
    works on this owner-role connection) so the refusal that follows is
    meaningful and not a false pass from some unrelated failure. This half is
    skipped unless TEST_POSTGRES_DSN is set.
"""

from __future__ import annotations

import logging
import os

import pytest
import pytest_asyncio

from csreg_scanner import sources

_LOG = logging.getLogger("test_sources")


# ===========================================================================
# Unit 1: _is_select_only -- the shape guard.
# ===========================================================================
#
# Weighted toward REJECTION cases: accepting a plain SELECT proves nothing about
# safety; rejecting stacking and non-SELECT is the guard. The happy-path accepts
# are here only to prove the guard isn't stuck-closed (refusing valid queries).


def test_rejects_statement_stacking():
    """The guard: a stacked statement (SELECT then DROP) must be refused.

    An internal ';' means a second statement. If this is ever accepted, the
    fail-fast at construction is defeated and a stacked write reaches the DB
    layer (where, yes, the readonly role/transaction should still stop it -- but
    the point of the shape check is to refuse it earlier and louder).
    """
    assert sources._is_select_only("SELECT 1; DROP TABLE servers") is False


def test_rejects_non_select_statements():
    """Anything not starting in SELECT / WITH...SELECT is refused."""
    assert sources._is_select_only("DELETE FROM servers") is False
    assert sources._is_select_only("UPDATE servers SET x = 1") is False
    assert sources._is_select_only("INSERT INTO servers VALUES ('x')") is False
    assert sources._is_select_only("DROP TABLE servers") is False


def test_rejects_empty_and_whitespace():
    """Empty / whitespace-only query is not a SELECT."""
    assert sources._is_select_only("") is False
    assert sources._is_select_only("   \n  ") is False


def test_accepts_plain_select():
    """Not stuck-closed: a normal single SELECT is accepted."""
    assert sources._is_select_only("SELECT server_name FROM servers") is True


def test_accepts_cte_select():
    """A WITH...SELECT CTE that resolves to a read is accepted."""
    q = "WITH recent AS (SELECT server_name FROM servers) SELECT * FROM recent"
    assert sources._is_select_only(q) is True


def test_accepts_single_trailing_semicolon():
    """A single trailing ';' is a terminated statement, not stacking -> accepted.

    The guard strips exactly one trailing ';' before checking for internal ones,
    so a normal terminated query is fine but 'SELECT 1; SELECT 2' is not.
    """
    assert sources._is_select_only("SELECT server_name FROM servers;") is True


def test_accepts_leading_whitespace_and_mixed_case():
    """Leading whitespace / mixed case must not fool the matcher.

    The regex is case-insensitive and tolerates leading whitespace; assert that
    so a future 'tighten the regex' change can't accidentally start rejecting
    legitimately-formatted queries (fail-closed) or, worse, matching loosely.
    """
    assert sources._is_select_only("   \n  sElEcT 1") is True


def test_KNOWN_HOLE_data_modifying_cte_passes_shape_check():
    """DOCUMENTED WEAKNESS -- read this before trusting _is_select_only.

    A data-modifying CTE (WITH x AS (INSERT ... RETURNING ...) SELECT ... ) is a
    write, but it *starts* with WITH...SELECT, so the shape check matches it and
    returns True. The source code says this outright: the shape check cannot
    catch it; the readonly TRANSACTION in fetch() is what actually refuses it
    (see test_readonly_transaction_refuses_data_modifying_cte below).

    This test asserts the hole EXISTS on purpose. It is not a bug report -- it
    is a tripwire: if someone later "hardens" _is_select_only to reject this,
    this test will fail and force a conversation about whether the shape check is
    being wrongly promoted to a security boundary it was never meant to be.
    """
    cte = (
        "WITH x AS (INSERT INTO servers VALUES ('evil') RETURNING server_name) "
        "SELECT * FROM x"
    )
    assert sources._is_select_only(cte) is True  # <-- deliberately True


# ===========================================================================
# Unit 2: PostgresSource.__init__ -- the guard is actually WIRED to construction.
# ===========================================================================
#
# Construction does no I/O (the pool is built lazily in connect()), so these run
# with a dummy DSN and never touch a database.


def test_construction_rejects_non_select_query():
    """A bad query must raise at construction, before any connection exists.

    This proves the shape check is connected to __init__, not merely defined.
    A refactor that dropped the check would sail past this test only if it also
    stopped raising -- which is exactly the regression we want to catch.
    """
    with pytest.raises(ValueError):
        sources.PostgresSource(
            dsn="postgresql://unused/db",
            query="DELETE FROM servers",
            log=_LOG,
        )


def test_construction_accepts_select_query():
    """A valid SELECT constructs cleanly and no connection is attempted.

    Asserting the query is stored (and that construction didn't try to connect)
    keeps the 'lazy pool' contract honest: __init__ validates shape only.
    """
    src = sources.PostgresSource(
        dsn="postgresql://unused/db",
        query="SELECT server_name FROM servers",
        log=_LOG,
    )
    assert src.query == "SELECT server_name FROM servers"
    assert src._pool is None  # not connected at construction


# ===========================================================================
# Unit 4: real Postgres -- row cleaning AND the readonly transaction.
# ===========================================================================
#
# These need a live Postgres. TEST_POSTGRES_DSN must be an OWNER-role DSN (full
# write perms) so the readonly tests prove the TRANSACTION refuses writes, not
# the role. If the DSN is unset, everything below is skipped -- local runs stay
# green, exactly like the existing db tests.

_PG_DSN = os.environ.get("TEST_POSTGRES_DSN")
_pg = pytest.mark.skipif(_PG_DSN is None, reason="TEST_POSTGRES_DSN not set")

# Imported lazily so a machine without asyncpg can still collect the file.
try:
    import asyncpg
    from asyncpg.exceptions import ReadOnlySQLTransactionError
except ImportError:  # pragma: no cover
    asyncpg = None
    ReadOnlySQLTransactionError = None


@pytest_asyncio.fixture
async def pg_pool():
    """A private asyncpg pool on the owner DSN, with a scratch schema.

    Each test gets a clean scratch schema (dropped + recreated) so a crashed
    prior run can't leak rows. Owner role is REQUIRED here -- the readonly tests
    below only mean something if this connection could otherwise write.
    """
    pool = await asyncpg.create_pool(_PG_DSN, min_size=1, max_size=2)
    async with pool.acquire() as conn:
        await conn.execute(
            "DROP SCHEMA IF EXISTS csreg_test CASCADE; CREATE SCHEMA csreg_test;"
        )
    try:
        yield pool
    finally:
        async with pool.acquire() as conn:
            await conn.execute("DROP SCHEMA IF EXISTS csreg_test CASCADE;")
        await pool.close()


@_pg
async def test_positive_control_owner_can_write(pg_pool):
    """POSITIVE CONTROL -- run first, so the refusal tests are meaningful.

    Prove a plain write works on this connection outside any readonly wrapper.
    If THIS fails, the readonly assertions below would be false passes ('no
    write happened' for the wrong reason), so this control must pass first.
    """
    async with pg_pool.acquire() as conn:
        await conn.execute("CREATE TABLE csreg_test.t (name text)")
        await conn.execute("INSERT INTO csreg_test.t VALUES ('matrix.org')")
        got = await conn.fetchval("SELECT name FROM csreg_test.t")
    assert got == "matrix.org"


@_pg
async def test_readonly_transaction_refuses_plain_write(pg_pool):
    """The guard: a write inside a readonly transaction must be refused.

    Same owner connection that just proved it CAN write (control above). Inside
    conn.transaction(readonly=True), an INSERT must raise
    ReadOnlySQLTransactionError (SQLSTATE 25006). This is the enforced half of
    the SELECT-only promise.
    """
    async with pg_pool.acquire() as conn:
        await conn.execute("CREATE TABLE csreg_test.t (name text)")
        with pytest.raises(ReadOnlySQLTransactionError):
            async with conn.transaction(readonly=True):
                await conn.execute("INSERT INTO csreg_test.t VALUES ('evil')")


@_pg
async def test_readonly_transaction_refuses_data_modifying_cte(pg_pool):
    """The hole from _is_select_only, CLOSED by the layer that's meant to close it.

    test_KNOWN_HOLE_... proved the shape check lets a data-modifying CTE through.
    This proves the readonly transaction catches it anyway: the exact statement
    the shape check can't distinguish from a read is refused at execution. This
    is the pair that makes the file's defense-in-depth claim true rather than
    asserted.
    """
    cte = (
        "WITH x AS (INSERT INTO csreg_test.t VALUES ('evil') RETURNING name) "
        "SELECT * FROM x"
    )
    async with pg_pool.acquire() as conn:
        await conn.execute("CREATE TABLE csreg_test.t (name text)")
        with pytest.raises(ReadOnlySQLTransactionError):
            async with conn.transaction(readonly=True):
                await conn.fetch(cte)


@_pg
async def test_fetch_cleans_rows_drops_garbage(pg_pool):
    """Row cleaning against REAL export shapes: what actually reaches the queue.

    The rows below are real examples pulled from an actual `SELECT server_name`
    dump (public federation server names, ~2 per shape), plus the true garbage
    that dump contained. Each row's keep/drop bucket was verified against the
    real validate_server_name (util.py) rather than assumed -- see the two
    surprises called out below.

    Why real shapes matter: a synthetic fixture would not have included IDN
    (punycode) server names or a leaked column header, and would have guessed
    wrong about the numeric-id case. This test documents what PostgresSource
    genuinely ships downstream, surprises included.

    NOTE this is a small curated sample, NOT the full 43k dump. The point is
    shape coverage a maintainer can read, not volume. A volume/perf test, if
    ever wanted, is a separate thing run off the full file on the runner.
    """
    # (value_to_insert, must_survive_cleaning)
    rows = [
        # --- valid server names: MUST be kept ---
        ("sagbot.com", True),                       # plain domain
        ("matrix.thekitten.space", True),           # plain subdomain
        # IDN / punycode -- valid server names. A synthetic fixture would have
        # missed these entirely; validate_server_name accepts them, so they must
        # NOT be dropped.
        ("xn--80aaajme3ab7c.xn--p1ai", True),
        ("matrix.xn--94b8erb2a.xn--54b7fta0cc", True),
        ("matrix.rabbee.cn:4433", True),            # host:port
        ("91.218.246.70.sslip.io:8443", True),      # sslip hostname + port (NOT an IP)
        ("59.110.235.135", True),                   # IPv4 literal (real export row)
        ("[2a0b:64c0:1::24d]", True),               # bracketed IPv6

        # --- SYNTHETIC edge probe (kept, not dropped): a bare integer ---
        # NOTE: this is NOT from the real export -- the real data has zero
        # bare-integer rows. It's a deliberate synthetic probe of a
        # validate_server_name property: a bare number LOOKS like garbage but
        # returns True, because per the Matrix grammar a server name is
        # hostname[:port] and a bare number is a syntactically valid dotless
        # hostname. So IF such a row ever appeared it WOULD reach the queue (it
        # just won't resolve -> scan records `unknown`). Asserted kept so the
        # test tells the truth about the validator; flip it and add a rule to
        # validate_server_name if numeric-only rows should be dropped.
        # (Historical aside: an earlier data sample contained '59110235135',
        # which turned out to be '59.110.235.135' with the dots eaten by an
        # Excel copy-paste round-trip -- a transport artifact, not real data.)
        ("59110235135", True),

        # --- true garbage: MUST be dropped ---
        ("server_name", False),   # the SQL column header leaked into the dump
        (None, False),            # NULL row
        ("", False),              # empty string
        ("   ", False),           # whitespace only
    ]

    async with pg_pool.acquire() as conn:
        await conn.execute("CREATE TABLE csreg_test.src (name text)")
        for value, _keep in rows:
            await conn.execute(
                "INSERT INTO csreg_test.src (name) VALUES ($1)",
                None if value is None else str(value),
            )

    src = sources.PostgresSource(
        dsn=_PG_DSN,
        query="SELECT name FROM csreg_test.src",
        log=_LOG,
    )
    await src.connect()
    try:
        out = await src.fetch()
    finally:
        await src.close()

    out_set = set(out)
    for value, keep in rows:
        if value is None:
            # NULL can't be membership-checked as a string; its absence is
            # covered by the None-not-in-out assertion below.
            continue
        expected = str(value)
        if keep:
            assert expected in out_set, f"expected kept but dropped: {expected!r}"
        else:
            assert expected not in out_set, f"expected dropped but kept: {expected!r}"

    # NULL specifically must never appear as a value.
    assert None not in out
