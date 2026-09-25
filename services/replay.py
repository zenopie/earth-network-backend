"""Replay protection for AdMob SSV callbacks.

Google will retry a callback, and an attacker will happily replay one, so a
transaction_id may be honoured exactly once. SQLite rather than a JSON file: the
id set is append-only and read on every request, and a file that gets rewritten
wholesale loses entries the moment two callbacks land together.
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
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS used_by_address ON used_transactions (address, granted_at)"
        )
        _conn.execute("CREATE INDEX IF NOT EXISTS used_by_time ON used_transactions (granted_at)")
        _conn.commit()
    return _conn


class LimitReached(Exception):
    """The payout would go over a rolling 24-hour limit; nothing was claimed."""


_DAY = 86400


def claim(transaction_id: str, address: str) -> bool:
    """Records a transaction_id, returning False if it was already used.

    The insert is the claim: a UNIQUE violation is how a replay is detected, so
    two concurrent callbacks with the same id cannot both win.

    Raises LimitReached, before claiming, when the address or the service as a
    whole has already been paid its allowance in the last 24 hours. Every
    genuine callback was otherwise payable, so the hot wallet could be drained
    as fast as someone could farm ad views. Counted from this table, under the
    same lock as the insert, so concurrent callbacks cannot both squeeze under
    a limit; a released id no longer counts, because it moved nothing.
    """
    with _lock:
        since = int(time.time()) - _DAY
        (mine,) = _db().execute(
            "SELECT COUNT(*) FROM used_transactions WHERE address = ? AND granted_at > ?",
            (address, since),
        ).fetchone()
        if mine >= config.ADS_MAX_PER_ADDRESS_PER_DAY:
            raise LimitReached("address")
        (everyone,) = _db().execute(
            "SELECT COUNT(*) FROM used_transactions WHERE granted_at > ?", (since,)
        ).fetchone()
        if everyone >= config.ADS_MAX_PER_DAY:
            raise LimitReached("daily")
        try:
            _db().execute(
                "INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, ?, ?)",
                (transaction_id, address, int(time.time())),
            )
            _db().commit()
            return True
        except sqlite3.IntegrityError:
            return False


def release(transaction_id: str) -> None:
    """Gives a claimed id back, for when the grant itself failed.

    Without this a user who watched an ad the chain then refused to pay out on
    would have burned it — the id would be spent with nothing to show for it.
    """
    with _lock:
        _db().execute("DELETE FROM used_transactions WHERE transaction_id = ?", (transaction_id,))
        _db().commit()
