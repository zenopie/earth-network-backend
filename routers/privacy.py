"""The shielded pool's public data, as compact streams for wallets to sync.

Full ranges only. A wallet downloads every note commitment and ciphertext,
every nullifier and every identity leaf, rebuilds the trees and trial-decrypts
locally; there is deliberately no endpoint that answers anything about one
user (a note by owner, the path to my leaf, "is my nullifier spent"), because
asking would tell this server which notes are whose. Pages are addressed by
position, index or height alone, never by anything a wallet derives from its
keys.

    GET /privacy/status                  -> chain_id, genesis, base, synced height, ...

and, under base = /privacy/<chain_id>/<genesis>:

    GET {base}/status
    GET {base}/notes?from_pos=&limit=            [position, height, cm, ciphertext, amount, owner_pk, rho, rcm]
    GET {base}/nullifiers?from_height=&limit=    [[height, [nf, ...]], ...]
    GET {base}/identity?from_index=&limit=       [index, height, leaf, zeroed_height, time]
    GET {base}/identity/zeroed?from_height=&limit=  [[height, [index, ...]], ...]
    GET {base}/roots/latest
    GET {base}/rates?epoch=
    GET {base}/stake/notes?from_pos=&limit=          [position, height, cm, ciphertext]  (format 2)
    GET {base}/stake/nullifiers?from_height=&limit=  [[height, [nf, ...]], ...]
    GET {base}/stake/nullifier-tree?from_index=&limit=  [index, nf, height]
    GET {base}/stake/roots?from_height=&limit=       [height, root, tree_size, time]
    GET {base}/stake/snapshots?from_height=&limit=   [height, proposal_id, root, tree_size, nf_root, nf_size]
    GET {base}/handles?from_index=&limit=            [handle, address, status, expires_at, renewal_until, owner]
    GET {base}/debt_rows?from_index=&limit=          [index, key, retained, height, updated_height]

genesis is the first 16 hex digits (lowercase) of the hash of the chain's
first block. earth-1 has been relaunched under the same chain id, so the chain
id alone does not name a chain; the pair does. A path naming any other chain
is 404 (no-store), so a page some CDN cached as immutable for an earlier
chain can never be served to a wallet following this one: the wallet reads
`base` from the unkeyed /privacy/status (cached 2 s) and only ever asks for
URLs under it. A wallet should keep the (chain_id, genesis) its local sync
was built from and start over when status names another.

The stake streams are x/shieldedstaking's stake note tree (owner-locked
derth/<valoper> notes), served exactly like the pool's. An undelegation's
payout is pool notes (ordinary minted rows of /notes, split ones sharing a
ciphertext), not stake notes. Every stake note is a stake proof output (the
chain mints none) with its 201-byte wallet stake ciphertext, the slash label
inside: stake rows are format STAKE_NOTE_FORMAT
(2), [position, height, cm, ciphertext], stated on every page ("format") and
in status ("stake_note_format"). Every pool note but an open one has a ciphertext
(minted: the 177-byte amount-blind v2 one). An open note (the referral note
the chain mints to a referrer handle's address, chain ORCHARD_DESIGN.md
section 16) has ciphertext null and its public opening in owner_pk, rho and
rcm (hex), null on every other row; the owner's wallet matches rows whose
owner_pk is its own and checks cm = H(TAG_CM, AssetID(denom), amount,
PC(owner_pk, rho, rcm)). Note rows are format NOTE_FORMAT (2), stated on
every notes page ("format") and in status ("note_format").

The stake nullifier tree (x/shieldedstaking, ORCHARD_DESIGN.md section 15)
is an indexed Merkle tree whose leaves are in insertion order: a wallet
proving a stake vote rebuilds it from the first nf_size - 1 values of
/stake/nullifier-tree (leaf indexes 1, 2, ...; leaf 0 is the sentinel) and
checks its root against the proposal snapshot's nf_root. The index refuses a
gap or a repeat in the leaf indexes, so the stream is exactly the chain's
insertion order.

The slash debt tree (zk/debt, chain ORCHARD_DESIGN.md section 20.6) is
served whole by leaf index like the stake nullifier tree: every row (a
slashed redelegation's move key and what its exposure is still worth), the
root at the synced height and the chain's window_seconds / clear_before, so
a wallet clearing a label or voting a labelled note rebuilds the tree and
proves against the current debt_root without asking about its own move. A
row can be rewritten (a later slash: retained falls), so no page is
immutable; a wallet whose rebuilt root differs from `root` reads every page
again.

The handle directory (x/personhood handles, services/privacy/handles) is
served whole, like every other stream: there is no endpoint for one handle,
so a wallet paying a handle does not tell this server which. It is a
snapshot of the chain's Handles query at one height (`height`, block time
`time`), in handle order, paged by place in it (from_index, aligned). A
snapshot is replaced whole when the directory changes, so a wallet reads
pages 0 .. size-1 and starts over if `height` differs between its pages.
status is the chain's at `time`: "live" resolves (pay it, name it as a
referrer), "renewal" and "free" do not; a wallet also treats a "live" entry
whose expires_at has passed by its own clock as not resolving. owner (the
sixth element) is the handle-scope nullifier holding the handle, 64
lowercase hex, "" for a handle never claimed: a wallet knows a handle is its
own by owner equal to its own handle-scope nullifier, never by the address
alone. The stream has no format number. `stale` (here and handles_stale in
status) is true while the snapshot is HANDLES_STALE_BLOCKS or more behind
the first handle event the index has applied since it (audit-5 L5, audit-6
L2): a handle may name another address by now, so a wallet should not pay a
handle from it.

Hex for 32-byte values, standard base64 for ciphertexts, rows as arrays (the
field order is in each response's "fields"). Responses are gzip'd by the app.
The web wallet reads them cross-origin: services/privacygate adds CORS
(Access-Control-Allow-Origin: https://erth.network on every response,
local dev origins reflected and uncached; no credentials).

Caching: a page that ends because it hit its limit covers a closed range that
can never change (notes, nullifiers and zeroings are append-only and blocks
are final), so it is served immutable and any CDN can keep it. The page that
reaches the synced tip, the identity leaves (a leaf can be zeroed later),
roots, rates and status get short max-ages. A page is immutable only once
every height in it has passed the indexer's tree-size check (meta
verified_height), and while the index is halted every {base}/* answer is
503 no-store; /privacy/status still says why (audit-5 L6).

Paging (audit-4 B3): limit is one of PRIVACY_PAGE_SIZES (100, 1000) and
nothing else, and a position- or index-paged stream (notes, identity,
stake/notes, stake/nullifier-tree, debt_rows, handles) takes only a
page-aligned cursor: from_pos / from_index a multiple of limit, else 400.
Page k of size L is exactly [k*L, (k+1)*L). Every client asks for the same
few URLs, so one CDN entry serves them all, and an uncached page is not a
URL an attacker can mint at will. A wallet whose sync ends mid-page asks
for the page containing its cursor and skips the rows it holds.
Height-paged streams end at a block boundary, so their cursor
(next_height) cannot be aligned; their rows are small (32-byte values) and
they share the limits on sizes, the per-client rate and the concurrency
cap (services/privacygate) with the rest. The gate also refuses (400,
no-store) any spelling of a URL but the canonical one: unknown or repeated
parameters, integers with leading zeros, signs or percent-encoding
(audit-5 M2), so one page is one cache key.
"""
import base64
import sqlite3
import threading
from contextlib import contextmanager

from fastapi import APIRouter, Depends, HTTPException, Query, Response

import config
from services.privacy import store as store_mod
from services.zk.debt import EMPTY_ROOT as DEBT_EMPTY_ROOT

GENESIS_PREFIX_HEX = 16
# SQLite integers are signed 64-bit: a larger query parameter is a 422, not
# an OverflowError (500) at the bind.
MAX_INT = 2**63 - 1

IMMUTABLE = "public, max-age=31536000, immutable"
TIP = "public, max-age=2"
SHORT = "public, max-age=10"

_local = threading.local()


def _db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None or getattr(_local, "path", None) != config.INDEX_DB:
        if conn is not None:
            conn.close()
        conn = store_mod.connect(config.INDEX_DB, readonly=True)
        _local.conn, _local.path = conn, config.INDEX_DB
    return conn


@contextmanager
def _read():
    """This thread's reader connection inside one read transaction.

    Every query of a response — its rows and the synced height beside them —
    sees one snapshot. Otherwise a block the indexer committed between a
    page's row query and its synced-height query would be named as covered
    (next_height past it) without its rows, and a client following
    next_height would never see them.
    """
    c = _db()
    c.execute("BEGIN")
    try:
        yield c
    finally:
        c.execute("ROLLBACK")


def _meta(c: sqlite3.Connection, key: str) -> str | None:
    row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _synced(c: sqlite3.Connection) -> int:
    v = _meta(c, "last_height")
    return int(v) if v else 0


def _genesis(c: sqlite3.Connection) -> str | None:
    g = _meta(c, "genesis_hash")
    return g[:GENESIS_PREFIX_HEX] if g else None


def _base(c: sqlite3.Connection) -> str | None:
    chain_id, genesis = _meta(c, "chain_id"), _genesis(c)
    return f"/privacy/{chain_id}/{genesis}" if chain_id and genesis else None


def _handles_size(c: sqlite3.Connection) -> int:
    """Entries in the served directory (meta, not a COUNT(*) scan a request)."""
    v = _meta(c, "handles_size")
    return int(v) if v is not None else c.execute("SELECT COUNT(*) FROM handles").fetchone()[0]


def _this_chain(chain_id: str, genesis: str) -> None:
    """404 unless the path names the chain the index holds (see the module doc);
    503 while the index is halted (audit-5 L6): a halted index may hold
    blocks it has found to diverge from the chain, and serving them, let
    alone as immutable pages, would spread them through every cache."""
    with _read() as c:
        if chain_id != _meta(c, "chain_id") or genesis != _genesis(c) or genesis is None:
            raise HTTPException(status_code=404, detail="not the chain this index holds; read base from /privacy/status",
                                headers={"Cache-Control": "no-store"})
        if _meta(c, "halted"):
            raise HTTPException(status_code=503, detail="the index is halted (see /privacy/status); nothing is served from it",
                                headers={"Cache-Control": "no-store", "Retry-After": "60"})


def _verified(c: sqlite3.Connection) -> int:
    """The last height whose tree sizes the indexer compared with the chain's."""
    v = _meta(c, "verified_height")
    return int(v) if v else 0


def _closed(complete: bool, last_height: int, c: sqlite3.Connection) -> str:
    """IMMUTABLE for a complete page whose rows the indexer has verified up to, else TIP.

    A page is cached for a year, so it must never hold a block the indexer
    could still find to diverge: the tree-size check runs after a batch is
    committed, and only heights it passed are final here (audit-5 L6).
    """
    return IMMUTABLE if complete and last_height <= _verified(c) else TIP


router = APIRouter(tags=["privacy"])
chain = APIRouter(prefix="/privacy/{chain_id}/{genesis}", dependencies=[Depends(_this_chain)])


def _sizes() -> tuple[int, ...]:
    return tuple(n for n in config.PRIVACY_PAGE_SIZES if 0 < n <= config.PRIVACY_PAGE_MAX)


def _limit(limit: int | None) -> int:
    """The page size: PRIVACY_PAGE_DEFAULT, or one of PRIVACY_PAGE_SIZES (else 400)."""
    if limit is None:
        return config.PRIVACY_PAGE_DEFAULT
    if limit not in _sizes():
        raise HTTPException(status_code=400, detail=f"limit must be one of {list(_sizes())}",
                            headers={"Cache-Control": "no-store"})
    return limit


def _aligned(start: int, limit: int | None, name: str) -> tuple[int, int]:
    """(page size, last position) of an aligned page [start, start + n); 400 if start is not a multiple of n."""
    n = _limit(limit)
    if start % n:
        raise HTTPException(status_code=400,
                            detail=f"{name} must be a multiple of limit ({n}): ask for page "
                                   f"{name}={start - start % n} and skip the rows before {start}",
                            headers={"Cache-Control": "no-store"})
    return n, min(start + n - 1, MAX_INT)


def _height_page(c: sqlite3.Connection, sql: str, from_height: int, limit: int):
    """Rows (height, value) of whole heights from from_height, about limit of them.

    A page never splits a height, so a client can page by height alone. One
    height holding more than limit rows (bounded by the chain's per-block cap
    on private txs) comes whole. Returns (rows, next_height, complete).
    """
    rows = c.execute(sql + " LIMIT ?", (from_height, limit + 1)).fetchall()
    if len(rows) <= limit:
        return rows, max(from_height, _synced(c) + 1), False
    boundary = rows[limit][0]
    page = [r for r in rows[:limit] if r[0] < boundary]
    if not page:
        page = c.execute(sql.replace("height >= ?", "height = ?"), (boundary,)).fetchall()
        return page, boundary + 1, True
    return page, boundary, True


def _group(rows, fmt) -> list:
    out: list = []
    for h, v in rows:
        if not out or out[-1][0] != h:
            out.append([h, []])
        out[-1][1].append(fmt(v))
    return out


# Row formats, stated on every page ("format") and in status. A wallet
# refuses a page whose format it does not know.
NOTE_FORMAT = 2
NOTE_FIELDS = ["position", "height", "cm", "ciphertext", "amount", "owner_pk", "rho", "rcm"]
STAKE_NOTE_FORMAT = 2
STAKE_NOTE_FIELDS = ["position", "height", "cm", "ciphertext"]
DEBT_ROW_FIELDS = ["index", "key", "retained", "height", "updated_height"]


@router.get("/privacy/status")
@chain.get("/status")
def status(response: Response):
    with _read() as c:
        notes, ids, nfs = store_mod.counts(c)
        stake_notes, stake_nfs = store_mod.stake_counts(c)
        response.headers["Cache-Control"] = TIP
        last_time = _meta(c, "last_time")
        start = _meta(c, "start_height")
        return {
            "chain_id": _meta(c, "chain_id"),
            "genesis": _genesis(c),
            "genesis_hash": _meta(c, "genesis_hash"),
            "base": _base(c),
            "synced_height": _synced(c),
            "synced_time": int(last_time) if last_time else None,
            "start_height": int(start) if start else None,
            "notes": notes,
            "note_format": NOTE_FORMAT,
            "identity_leaves": ids,
            "nullifiers": nfs,
            "stake_notes": stake_notes,
            "stake_nullifiers": stake_nfs,
            "stake_nf_tree_size": store_mod.stake_nf_size(c),
            "stake_note_format": STAKE_NOTE_FORMAT,
            "debt_tree_size": store_mod.debt_size(c),
            "handles": _handles_size(c),
            "handles_height": int(_meta(c, "handles_height") or 0) or None,
            "handles_stale": store_mod.handles_stale(c, config.HANDLES_STALE_BLOCKS),
            "halted": _meta(c, "halted"),
        }


@chain.get("/notes")
def notes(response: Response, from_pos: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    _, last = _aligned(from_pos, limit, "from_pos")
    with _read() as c:
        rows = c.execute(
            "SELECT position, height, cm, ciphertext, amount, owner_pk, rho, rcm FROM notes"
            " WHERE position BETWEEN ? AND ? ORDER BY position",
            (from_pos, last),
        ).fetchall()
        complete = bool(rows) and rows[-1][0] == last
        response.headers["Cache-Control"] = _closed(complete, rows[-1][1] if rows else 0, c)
        return {
            "format": NOTE_FORMAT,
            "fields": NOTE_FIELDS,
            "synced_height": _synced(c),
            "from_pos": from_pos,
            "next_pos": rows[-1][0] + 1 if rows else from_pos,
            "complete": complete,
            "notes": [[p, h, cm.hex(), base64.b64encode(ct).decode() if ct else None, amt,
                       _hex_or_none(opk), _hex_or_none(rho), _hex_or_none(rcm)]
                      for p, h, cm, ct, amt, opk, rho, rcm in rows],
        }


@chain.get("/nullifiers")
def nullifiers(response: Response, from_height: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    with _read() as c:
        rows, nxt, complete = _height_page(
            c, "SELECT height, nf FROM nullifiers WHERE height >= ? ORDER BY height, seq", from_height, _limit(limit))
        response.headers["Cache-Control"] = _closed(complete, nxt - 1, c)
        return {
            "fields": ["height", "nullifiers"],
            "synced_height": _synced(c),
            "from_height": from_height,
            "next_height": nxt,
            "complete": complete,
            "blocks": _group(rows, bytes.hex),
        }


@chain.get("/identity")
def identity(response: Response, from_index: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    _, last = _aligned(from_index, limit, "from_index")
    with _read() as c:
        rows = c.execute(
            # time: the block time (unix seconds) of the leaf's height; every
            # applied block is in `blocks`, written in the same transaction.
            "SELECT l.idx, l.height, l.leaf, l.zeroed_height, b.time FROM identity_leaves l"
            " JOIN blocks b ON b.height = l.height WHERE l.idx BETWEEN ? AND ? ORDER BY l.idx",
            (from_index, last),
        ).fetchall()
        (size,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM identity_leaves").fetchone()
        # Not immutable: a leaf on this page may be zeroed later. Clients that
        # already hold a range follow /identity/zeroed instead of re-reading it.
        response.headers["Cache-Control"] = SHORT if rows and rows[-1][0] == last else TIP
        return {
            "fields": ["index", "height", "leaf", "zeroed_height", "time"],
            "synced_height": _synced(c),
            "size": size,
            "from_index": from_index,
            "next_index": rows[-1][0] + 1 if rows else from_index,
            "leaves": [[i, h, leaf.hex(), z, t] for i, h, leaf, z, t in rows],
        }


@chain.get("/identity/zeroed")
def identity_zeroed(response: Response, from_height: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    with _read() as c:
        rows, nxt, complete = _height_page(
            c, "SELECT height, idx FROM identity_writes WHERE zeroed = 1 AND height >= ? ORDER BY height, seq",
            from_height, _limit(limit))
        response.headers["Cache-Control"] = _closed(complete, nxt - 1, c)
        return {
            "fields": ["height", "indexes"],
            "synced_height": _synced(c),
            "from_height": from_height,
            "next_height": nxt,
            "complete": complete,
            "blocks": _group(rows, int),
        }


def _root(c: sqlite3.Connection, table: str):
    row = c.execute(f"SELECT root, tree_size, height, time FROM {table} ORDER BY height DESC LIMIT 1").fetchone()
    if row is None:
        return None
    return {"root": row[0].hex(), "tree_size": row[1], "height": row[2], "time": row[3]}


@chain.get("/roots/latest")
def roots_latest(response: Response):
    with _read() as c:
        response.headers["Cache-Control"] = TIP
        return {
            "synced_height": _synced(c),
            "note": _root(c, "note_roots"),
            "identity": _root(c, "identity_roots"),
            "stake": _root(c, "stake_roots"),
        }


@chain.get("/rates")
def rates(response: Response, epoch: int | None = Query(None, ge=0, le=MAX_INT)):
    """Each validator's derth rate: at the end of `epoch`, or the latest."""
    with _read() as c:
        fields = ["validator", "rate", "supply", "epoch", "height"]
        (latest_epoch,) = c.execute("SELECT MAX(epoch) FROM rates").fetchone()
        if epoch is None:
            rows = c.execute(
                "SELECT r.validator, r.rate, r.supply, r.epoch, r.height FROM rates r"
                " JOIN (SELECT validator, MAX(height) AS h FROM rates GROUP BY validator) l"
                " ON r.validator = l.validator AND r.height = l.h ORDER BY r.validator"
            ).fetchall()
            response.headers["Cache-Control"] = "public, max-age=30"
        else:
            rows = c.execute(
                "SELECT validator, rate, supply, epoch, height FROM rates WHERE epoch = ? ORDER BY validator, height",
                (epoch,),
            ).fetchall()
            # An epoch older than the latest is closed; the latest may still be
            # joined by a validator whose epoch end was retried.
            closed = latest_epoch is not None and epoch < latest_epoch
            response.headers["Cache-Control"] = "public, max-age=86400" if closed else "public, max-age=30"
        return {
            "fields": fields,
            "synced_height": _synced(c),
            "epoch": epoch,
            "latest_epoch": latest_epoch,
            "rates": [list(r) for r in rows],
        }


def _hex_or_none(v: bytes | None) -> str | None:
    return None if v is None else v.hex()


@chain.get("/stake/notes")
def stake_notes(response: Response, from_pos: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    _, last = _aligned(from_pos, limit, "from_pos")
    with _read() as c:
        rows = c.execute(
            "SELECT position, height, cm, ciphertext FROM stake_notes"
            " WHERE position BETWEEN ? AND ? ORDER BY position",
            (from_pos, last),
        ).fetchall()
        complete = bool(rows) and rows[-1][0] == last
        response.headers["Cache-Control"] = _closed(complete, rows[-1][1] if rows else 0, c)
        return {
            "format": STAKE_NOTE_FORMAT,
            "fields": STAKE_NOTE_FIELDS,
            "synced_height": _synced(c),
            "from_pos": from_pos,
            "next_pos": rows[-1][0] + 1 if rows else from_pos,
            "complete": complete,
            "notes": [[p, h, cm.hex(), base64.b64encode(ct).decode()] for p, h, cm, ct in rows],
        }


@chain.get("/stake/nullifiers")
def stake_nullifiers(response: Response, from_height: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    with _read() as c:
        rows, nxt, complete = _height_page(
            c, "SELECT height, nf FROM stake_nullifiers WHERE height >= ? ORDER BY height, idx", from_height, _limit(limit))
        response.headers["Cache-Control"] = _closed(complete, nxt - 1, c)
        return {
            "fields": ["height", "nullifiers"],
            "synced_height": _synced(c),
            "from_height": from_height,
            "next_height": nxt,
            "complete": complete,
            "blocks": _group(rows, bytes.hex),
        }


@chain.get("/stake/nullifier-tree")
def stake_nullifier_tree(response: Response, from_index: int = Query(0, ge=0, le=MAX_INT),
                         limit: int | None = Query(None, ge=1, le=MAX_INT)):
    """The stake nullifier tree's values by leaf index (insertion order), from from_index.

    Leaf 0 is the sentinel and never a row; the first value is leaf 1, so
    the first page (from_index=0, aligned like every index cursor) holds
    leaves 1 .. limit-1. size is the tree's leaf count as the chain counts
    it (values + 1, 0 when empty). A wallet building a vote at a snapshot
    takes leaves 1 .. nf_size - 1 and rebuilds the indexed tree in that
    order.
    """
    _, last = _aligned(from_index, limit, "from_index")
    with _read() as c:
        rows = c.execute(
            "SELECT idx, nf, height FROM stake_nullifiers WHERE idx BETWEEN ? AND ? ORDER BY idx",
            (from_index, last),
        ).fetchall()
        complete = bool(rows) and rows[-1][0] == last
        response.headers["Cache-Control"] = _closed(complete, rows[-1][2] if rows else 0, c)
        return {
            "fields": ["index", "nullifier", "height"],
            "synced_height": _synced(c),
            "size": store_mod.stake_nf_size(c),
            "from_index": from_index,
            "next_index": rows[-1][0] + 1 if rows else max(from_index, 1),
            "complete": complete,
            "nullifiers": [[i, nf.hex(), h] for i, nf, h in rows],
        }


@chain.get("/stake/snapshots")
def stake_snapshots(response: Response, from_height: int = Query(0, ge=0, le=MAX_INT),
                    limit: int | None = Query(None, ge=1, le=MAX_INT)):
    """Every proposal snapshot (the trees a proposal's stake votes prove against), by height.

    root is empty ("") for a snapshot taken before the stake note tree had a
    root. nf_size counts the sentinel (0: no nullifier yet).
    """
    with _read() as c:
        rows, nxt, complete = _height_page(
            c, "SELECT height, proposal_id, root, tree_size, nf_root, nf_size FROM stake_snapshots"
               " WHERE height >= ? ORDER BY height, proposal_id", from_height, _limit(limit))
        response.headers["Cache-Control"] = _closed(complete, nxt - 1, c)
        return {
            "fields": ["height", "proposal_id", "root", "tree_size", "nf_root", "nf_size"],
            "synced_height": _synced(c),
            "from_height": from_height,
            "next_height": nxt,
            "complete": complete,
            "snapshots": [[h, p, r.hex(), ts, nr.hex(), ns] for h, p, r, ts, nr, ns in rows],
        }


@chain.get("/stake/roots")
def stake_roots(response: Response, from_height: int = Query(0, ge=0, le=MAX_INT), limit: int | None = Query(None, ge=1, le=MAX_INT)):
    """Every stake root the chain recorded (one per block that moved the tree), oldest first.

    A wallet proves a stake note against any root still in the chain's window
    (stake_root_window_seconds) or, for a stake vote, against the proposal's
    snapshot root; this stream is every candidate, keyed by height alone.
    """
    with _read() as c:
        n = _limit(limit)
        rows = c.execute(
            "SELECT height, root, tree_size, time FROM stake_roots WHERE height >= ? ORDER BY height LIMIT ?",
            (from_height, n),
        ).fetchall()
        complete = len(rows) == n
        response.headers["Cache-Control"] = _closed(complete, rows[-1][0] if rows else 0, c)
        return {
            "fields": ["height", "root", "tree_size", "time"],
            "synced_height": _synced(c),
            "from_height": from_height,
            "next_height": rows[-1][0] + 1 if complete else max(from_height, _synced(c) + 1),
            "complete": complete,
            "roots": [[h, r.hex(), size, t] for h, r, size, t in rows],
        }


def _meta_int(c: sqlite3.Connection, key: str) -> int | None:
    v = _meta(c, key)
    return int(v) if v is not None else None


@chain.get("/debt_rows")
def debt_rows(response: Response, from_index: int = Query(0, ge=0, le=MAX_INT),
              limit: int | None = Query(None, ge=1, le=MAX_INT)):
    """The slash debt tree's rows by leaf index (insertion order), each with its latest retained.

    Leaf 0 is the sentinel and never a row; the first row is leaf 1, so the
    first page (from_index=0, aligned like every index cursor) holds leaves
    1 .. limit-1. size is the leaf count as the chain counts it (rows + 1, 0
    when empty); root is the tree's root at synced_height (the last row
    event's, the empty root before any), root_height the block that wrote
    it. window_seconds and clear_before are the chain's (Query/DebtTree) at
    clear_before_height, the indexer's last check: a stake proof clearing a
    label names clear_before (at most the chain's at its block) and
    debt_root = root. Every response is short-lived: a later slash rewrites
    a row in place.
    """
    _, last = _aligned(from_index, limit, "from_index")
    with _read() as c:
        rows = c.execute(
            "SELECT idx, key, retained, height, updated_height FROM debt_rows WHERE idx BETWEEN ? AND ? ORDER BY idx",
            (from_index, last),
        ).fetchall()
        size = store_mod.debt_size(c)
        root = store_mod.debt_root(c)
        response.headers["Cache-Control"] = TIP
        return {
            "format": 1,
            "fields": DEBT_ROW_FIELDS,
            "synced_height": _synced(c),
            "size": size,
            "root": (root[0] if root else DEBT_EMPTY_ROOT.to_bytes(32, "big")).hex(),
            "root_height": root[1] if root else None,
            "window_seconds": _meta_int(c, "debt_window_seconds"),
            "clear_before": _meta_int(c, "debt_clear_before"),
            "clear_before_height": _meta_int(c, "debt_checked_height"),
            "from_index": from_index,
            "next_index": rows[-1][0] + 1 if rows else max(from_index, 1),
            "complete": bool(rows) and rows[-1][0] == last,
            "rows": [[i, k.hex(), r, h, u] for i, k, r, h, u in rows],
        }


@chain.get("/handles")
def handle_directory(response: Response, from_index: int = Query(0, ge=0, le=MAX_INT),
                     limit: int | None = Query(None, ge=1, le=MAX_INT)):
    """The handle directory, every handle in order, from the snapshot's from_index-th.

    Never cached long: a snapshot is replaced whole whenever the directory
    changes. height / time are the block the snapshot was read at (null
    before the first); a client paging across a change sees height move and
    starts over.
    """
    _, last = _aligned(from_index, limit, "from_index")
    with _read() as c:
        rows = c.execute(
            "SELECT idx, handle, address, status, expires_at, renewal_until, owner FROM handles"
            " WHERE idx BETWEEN ? AND ? ORDER BY idx",
            (from_index, last),
        ).fetchall()
        size = _handles_size(c)
        height, when = _meta(c, "handles_height"), _meta(c, "handles_time")
        response.headers["Cache-Control"] = TIP
        return {
            "fields": ["handle", "address", "status", "expires_at", "renewal_until", "owner"],
            "synced_height": _synced(c),
            "height": int(height) if height else None,
            "time": int(when) if when else None,
            "size": size,
            # The snapshot is behind a handle event the index has seen
            # (audit-5 L5): a handle may name another address by now. A
            # wallet should not pay a handle from a stale directory.
            "stale": store_mod.handles_stale(c, config.HANDLES_STALE_BLOCKS),
            "from_index": from_index,
            "next_index": rows[-1][0] + 1 if rows else from_index,
            # This page reaches the end of the directory: nothing to ask after it.
            "last_page": last + 1 >= size,
            "handles": [list(r[1:]) for r in rows],
        }


router.include_router(chain)
