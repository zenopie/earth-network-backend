"""Replay protection and payout limits for gas grants.

A grant id — the passport key `passport:<nullifier>:<YYYY-MM-DD>` of a
registration grant — may be honoured exactly once, and a passport (every id
under `passport:<nullifier>:`) at most once in any `once_per` window (30
days): keyed by calendar month, a grant on the 31st and another on the 1st
were two grants a day apart. It is stored under its id
alone, with an empty address: the backend keeps nothing that names where the
note went. SQLite rather than a JSON file: the id set is
append-only and read on every request, and a file that gets rewritten wholesale
loses entries the moment two requests land together.

The table keeps its original name from the AdMob era, when the ids were SSV
transaction ids, and its address column from the device-attestation grants;
renaming either would drop the history the daily cap counts. The address
column now holds a grant's *kind* and nothing else: '' for a first
registration, 'switch' for a passport already registered moving to a new
identity (public on chain anyway). Each kind has its own daily cap, so
switches cannot spend the cap new registrants need (audit-4 B4).
"""
import sqlite3
import threading
import time

import config

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(config.STATE_DB, check_same_thread=False)
        _conn.execute(
            """CREATE TABLE IF NOT EXISTS used_transactions (
                   transaction_id TEXT PRIMARY KEY,
                   address        TEXT NOT NULL,
                   granted_at     INTEGER NOT NULL
               )"""
        )
        _conn.execute("CREATE INDEX IF NOT EXISTS used_by_time ON used_transactions (granted_at)")
        _conn.commit()
    return _conn


class LimitReached(Exception):
    """The payout would go over a rolling 24-hour limit; nothing was claimed."""


_DAY = 86400


def _granted_within(key_prefix: str, seconds: int) -> bool:
    """Whether any id starting with key_prefix was claimed in the last `seconds`.

    A range over the primary key (ids under one key share the prefix and
    nothing else sorts between it and prefix + U+10FFFF)."""
    row = _db().execute(
        "SELECT 1 FROM used_transactions WHERE transaction_id >= ? AND transaction_id < ? AND granted_at > ? LIMIT 1",
        (key_prefix, key_prefix + "\U0010ffff", int(time.time()) - seconds),
    ).fetchone()
    return row is not None


def peek(transaction_id: str, *, key_prefix: str | None = None, once_per: int | None = None) -> bool:
    """Whether a grant id is already claimed (or, with key_prefix, any id
    under it within once_per seconds). Read-only, for refusing a replay
    before the expensive check; claim() is still what decides."""
    with _lock:
        if key_prefix is not None and once_per is not None and _granted_within(key_prefix, once_per):
            return True
        row = _db().execute(
            "SELECT 1 FROM used_transactions WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
    return row is not None


def _paid_today(prefix: str, kind: str = "") -> int:
    since = int(time.time()) - _DAY
    (paid,) = _db().execute(
        "SELECT COUNT(*) FROM used_transactions WHERE granted_at > ? AND substr(transaction_id, 1, ?) = ?"
        " AND address = ?",
        (since, len(prefix), prefix, kind),
    ).fetchone()
    return paid


def limit_reached(prefix: str, max_per_day: int, kind: str = "") -> bool:
    """Whether claim() would raise LimitReached now. Read-only, for refusing
    before the expensive check; claim() is still what decides."""
    with _lock:
        return _paid_today(prefix, kind) >= max_per_day


def claim(transaction_id: str, *, prefix: str, max_per_day: int,
          key_prefix: str | None = None, once_per: int | None = None, kind: str = "") -> bool:
    """Records a grant id, returning False if it was already used.

    The insert is the claim: a UNIQUE violation is how a replay is detected, so
    two concurrent requests with the same id cannot both win.

    Raises LimitReached, before claiming, when ids of this `kind` starting
    with `prefix` have already been paid `max_per_day` times in the last 24
    hours. Counted from
    this table, under the same lock as the insert, so concurrent requests
    cannot both squeeze under the limit; a released id no longer counts,
    because it moved nothing.

    With key_prefix and once_per, also False when any id under key_prefix
    was claimed in the last once_per seconds — checked under the same lock
    as the insert.
    """
    with _lock:
        if _paid_today(prefix, kind) >= max_per_day:
            raise LimitReached("daily")
        if key_prefix is not None and once_per is not None and _granted_within(key_prefix, once_per):
            return False
        try:
            _db().execute(
                "INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, ?, ?)",
                (transaction_id, kind, int(time.time())),
            )
            _db().commit()
            return True
        except sqlite3.IntegrityError:
            return False


def release(transaction_id: str) -> None:
    """Gives a claimed id back, for when the grant itself failed.

    Without this a failed send would still count against the daily limit, and
    the passport could not try again this month.
    """
    with _lock:
        _db().execute("DELETE FROM used_transactions WHERE transaction_id = ?", (transaction_id,))
        _db().commit()
