"""Replay protection and payout limits for gas grants.

A grant id — the passport key `passport:<nullifier>:<YYYY-MM>` of a
registration grant — may be honoured exactly once. It is stored under its id
alone, with an empty address: the backend keeps nothing that names where the
note went. SQLite rather than a JSON file: the id set is
append-only and read on every request, and a file that gets rewritten wholesale
loses entries the moment two requests land together.

The table keeps its original name from the AdMob era, when the ids were SSV
transaction ids, and its address column from the device-attestation grants;
renaming either would drop the history the daily cap counts.
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


def peek(transaction_id: str) -> bool:
    """Whether a grant id is already claimed. Read-only, for refusing a replay
    before the expensive check; claim() is still what decides."""
    with _lock:
        row = _db().execute(
            "SELECT 1 FROM used_transactions WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
    return row is not None


def _paid_today(prefix: str) -> int:
    since = int(time.time()) - _DAY
    (paid,) = _db().execute(
        "SELECT COUNT(*) FROM used_transactions WHERE granted_at > ? AND substr(transaction_id, 1, ?) = ?",
        (since, len(prefix), prefix),
    ).fetchone()
    return paid


def limit_reached(prefix: str, max_per_day: int) -> bool:
    """Whether claim() would raise LimitReached now. Read-only, for refusing
    before the expensive check; claim() is still what decides."""
    with _lock:
        return _paid_today(prefix) >= max_per_day


def claim(transaction_id: str, *, prefix: str, max_per_day: int) -> bool:
    """Records a grant id, returning False if it was already used.

    The insert is the claim: a UNIQUE violation is how a replay is detected, so
    two concurrent requests with the same id cannot both win.

    Raises LimitReached, before claiming, when ids starting with `prefix` have
    already been paid `max_per_day` times in the last 24 hours. Counted from
    this table, under the same lock as the insert, so concurrent requests
    cannot both squeeze under the limit; a released id no longer counts,
    because it moved nothing.
    """
    with _lock:
        if _paid_today(prefix) >= max_per_day:
            raise LimitReached("daily")
        try:
            _db().execute(
                "INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, '', ?)",
                (transaction_id, int(time.time())),
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
