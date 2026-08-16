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
        _conn.commit()
    return _conn


def claim(transaction_id: str, address: str) -> bool:
    """Records a transaction_id, returning False if it was already used.

    The insert is the claim: a UNIQUE violation is how a replay is detected, so
    two concurrent callbacks with the same id cannot both win.
    """
    with _lock:
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
