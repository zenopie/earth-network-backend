"""The shielded pool's public data, as compact streams for wallets to sync.

Full ranges only. A wallet downloads every note commitment and ciphertext,
every nullifier and every identity leaf, rebuilds the trees and trial-decrypts
locally; there is deliberately no endpoint that answers anything about one
user (a note by owner, the path to my leaf, "is my nullifier spent"), because
asking would tell this server which notes are whose. Pages are addressed by
position, index or height alone, never by anything a wallet derives from its
keys.

    GET /privacy/status
    GET /privacy/notes?from_pos=&limit=            [position, height, cm, ciphertext, amount]
    GET /privacy/nullifiers?from_height=&limit=    [[height, [nf, ...]], ...]
    GET /privacy/identity?from_index=&limit=       [index, height, leaf, zeroed_height]
    GET /privacy/identity/zeroed?from_height=&limit=  [[height, [index, ...]], ...]
    GET /privacy/roots/latest
    GET /privacy/rates?epoch=
    GET /privacy/stake/notes?from_pos=&limit=          [position, height, cm, ciphertext, denom, amount, spc]
    GET /privacy/stake/nullifiers?from_height=&limit=  [[height, [nf, ...]], ...]
    GET /privacy/stake/roots?from_height=&limit=       [height, root, tree_size, time]

The stake streams are x/shieldedstaking's stake note tree (owner-locked
derth/<valoper> and unbond/<valoper>/<epoch> notes), served exactly like the
pool's: a stake note the chain minted has public denom, amount and stake pc
(spc) and a null ciphertext; a note a stake proof created has a ciphertext
and null denom, amount and spc.

Hex for 32-byte values, standard base64 for ciphertexts, rows as arrays (the
field order is in each response's "fields"). Responses are gzip'd by the app.

Caching: a page that ends because it hit its limit covers a closed range that
can never change (notes, nullifiers and zeroings are append-only and blocks
are final), so it is served immutable and any CDN can keep it. The page that
reaches the synced tip, the identity leaves (a leaf can be zeroed later),
roots, rates and status get short max-ages.
"""
import base64
import sqlite3
import threading

from fastapi import APIRouter, Query, Response

import config
from services.privacy import store as store_mod

router = APIRouter(prefix="/privacy", tags=["privacy"])

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


def _meta(c: sqlite3.Connection, key: str) -> str | None:
    row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _synced(c: sqlite3.Connection) -> int:
    v = _meta(c, "last_height")
    return int(v) if v else 0


def _limit(limit: int | None) -> int:
    if limit is None:
        return config.PRIVACY_PAGE_DEFAULT
    return max(1, min(limit, config.PRIVACY_PAGE_MAX))


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


@router.get("/status")
def status(response: Response):
    c = _db()
    notes, ids, nfs = store_mod.counts(c)
    stake_notes, stake_nfs = store_mod.stake_counts(c)
    response.headers["Cache-Control"] = TIP
    last_time = _meta(c, "last_time")
    start = _meta(c, "start_height")
    return {
        "chain_id": _meta(c, "chain_id"),
        "synced_height": _synced(c),
        "synced_time": int(last_time) if last_time else None,
        "start_height": int(start) if start else None,
        "notes": notes,
        "identity_leaves": ids,
        "nullifiers": nfs,
        "stake_notes": stake_notes,
        "stake_nullifiers": stake_nfs,
        "halted": _meta(c, "halted"),
    }


@router.get("/notes")
def notes(response: Response, from_pos: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    n = _limit(limit)
    rows = c.execute(
        "SELECT position, height, cm, ciphertext, amount FROM notes WHERE position >= ? ORDER BY position LIMIT ?",
        (from_pos, n),
    ).fetchall()
    complete = len(rows) == n
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
    return {
        "fields": ["position", "height", "cm", "ciphertext", "amount"],
        "synced_height": _synced(c),
        "from_pos": from_pos,
        "next_pos": rows[-1][0] + 1 if rows else from_pos,
        "complete": complete,
        "notes": [[p, h, cm.hex(), base64.b64encode(ct).decode(), amt] for p, h, cm, ct, amt in rows],
    }


@router.get("/nullifiers")
def nullifiers(response: Response, from_height: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    rows, nxt, complete = _height_page(
        c, "SELECT height, nf FROM nullifiers WHERE height >= ? ORDER BY height, seq", from_height, _limit(limit))
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
    return {
        "fields": ["height", "nullifiers"],
        "synced_height": _synced(c),
        "from_height": from_height,
        "next_height": nxt,
        "complete": complete,
        "blocks": _group(rows, bytes.hex),
    }


@router.get("/identity")
def identity(response: Response, from_index: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    n = _limit(limit)
    rows = c.execute(
        "SELECT idx, height, leaf, zeroed_height FROM identity_leaves WHERE idx >= ? ORDER BY idx LIMIT ?",
        (from_index, n),
    ).fetchall()
    (size,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM identity_leaves").fetchone()
    # Not immutable: a leaf on this page may be zeroed later. Clients that
    # already hold a range follow /identity/zeroed instead of re-reading it.
    response.headers["Cache-Control"] = SHORT if len(rows) == n else TIP
    return {
        "fields": ["index", "height", "leaf", "zeroed_height"],
        "synced_height": _synced(c),
        "size": size,
        "from_index": from_index,
        "next_index": rows[-1][0] + 1 if rows else from_index,
        "leaves": [[i, h, leaf.hex(), z] for i, h, leaf, z in rows],
    }


@router.get("/identity/zeroed")
def identity_zeroed(response: Response, from_height: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    rows, nxt, complete = _height_page(
        c, "SELECT height, idx FROM identity_writes WHERE zeroed = 1 AND height >= ? ORDER BY height, seq",
        from_height, _limit(limit))
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
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


@router.get("/roots/latest")
def roots_latest(response: Response):
    c = _db()
    response.headers["Cache-Control"] = TIP
    return {
        "synced_height": _synced(c),
        "note": _root(c, "note_roots"),
        "identity": _root(c, "identity_roots"),
        "stake": _root(c, "stake_roots"),
    }


@router.get("/rates")
def rates(response: Response, epoch: int | None = Query(None, ge=0)):
    """Each validator's derth rate: at the end of `epoch`, or the latest."""
    c = _db()
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


def _b64_or_none(v: bytes | None) -> str | None:
    return None if v is None else base64.b64encode(v).decode()


def _hex_or_none(v: bytes | None) -> str | None:
    return None if v is None else v.hex()


@router.get("/stake/notes")
def stake_notes(response: Response, from_pos: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    n = _limit(limit)
    rows = c.execute(
        "SELECT position, height, cm, ciphertext, denom, amount, spc FROM stake_notes"
        " WHERE position >= ? ORDER BY position LIMIT ?",
        (from_pos, n),
    ).fetchall()
    complete = len(rows) == n
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
    return {
        "fields": ["position", "height", "cm", "ciphertext", "denom", "amount", "spc"],
        "synced_height": _synced(c),
        "from_pos": from_pos,
        "next_pos": rows[-1][0] + 1 if rows else from_pos,
        "complete": complete,
        "notes": [[p, h, cm.hex(), _b64_or_none(ct), denom, amt, _hex_or_none(spc)]
                  for p, h, cm, ct, denom, amt, spc in rows],
    }


@router.get("/stake/nullifiers")
def stake_nullifiers(response: Response, from_height: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    c = _db()
    rows, nxt, complete = _height_page(
        c, "SELECT height, nf FROM stake_nullifiers WHERE height >= ? ORDER BY height, seq", from_height, _limit(limit))
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
    return {
        "fields": ["height", "nullifiers"],
        "synced_height": _synced(c),
        "from_height": from_height,
        "next_height": nxt,
        "complete": complete,
        "blocks": _group(rows, bytes.hex),
    }


@router.get("/stake/roots")
def stake_roots(response: Response, from_height: int = Query(0, ge=0), limit: int | None = Query(None, ge=1)):
    """Every stake root the chain recorded (one per block that moved the tree), oldest first.

    A wallet proves a stake note against any root still in the chain's window
    (stake_root_window_seconds) or, for a stake vote, against the proposal's
    snapshot root; this stream is every candidate, keyed by height alone.
    """
    c = _db()
    n = _limit(limit)
    rows = c.execute(
        "SELECT height, root, tree_size, time FROM stake_roots WHERE height >= ? ORDER BY height LIMIT ?",
        (from_height, n),
    ).fetchall()
    complete = len(rows) == n
    response.headers["Cache-Control"] = IMMUTABLE if complete else TIP
    return {
        "fields": ["height", "root", "tree_size", "time"],
        "synced_height": _synced(c),
        "from_height": from_height,
        "next_height": rows[-1][0] + 1 if complete else max(from_height, _synced(c) + 1),
        "complete": complete,
        "roots": [[h, r.hex(), size, t] for h, r, size, t in rows],
    }
