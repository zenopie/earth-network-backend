"""Replay protection and payout limits for gas grants.

A grant id — the passport key `passport:<nullifier>:<YYYY-MM>` for a
registration grant, the attested key for the device grants — may be honoured
exactly once. A registration grant is stored under its id alone, with an empty
address: it pays a shielded note, and the backend keeps nothing that names
where the note went. SQLite rather than a JSON file: the id set is
append-only and read on every request, and a file that gets rewritten wholesale
loses entries the moment two requests land together.

The table keeps its original name from the AdMob era, when the ids were SSV
transaction ids; renaming it would drop the history the daily caps count.
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


def claim(transaction_id: str, address: str = "") -> bool:
    """Records a grant id, returning False if it was already used.

    The insert is the claim: a UNIQUE violation is how a replay is detected, so
    two concurrent requests with the same id cannot both win.

    Raises LimitReached, before claiming, when the address or the service as a
    whole has already been paid its allowance in the last 24 hours. An
    attestation proves a device, not a person, so every genuine one is
    otherwise payable and the hot wallet could be drained as fast as one phone
    can make addresses. Counted from this table, under the same lock as the
    insert, so concurrent requests cannot both squeeze under a limit; a
    released id no longer counts, because it moved nothing.
    """
    with _lock:
        since = int(time.time()) - _DAY
        if address:
            # A note grant has no address (""); its id is already one per
            # passport per month.
            (mine,) = _db().execute(
                "SELECT COUNT(*) FROM used_transactions WHERE address = ? AND granted_at > ?",
                (address, since),
            ).fetchone()
            if mine >= config.GRANT_MAX_PER_ADDRESS_PER_DAY:
                raise LimitReached("address")
        (everyone,) = _db().execute(
            "SELECT COUNT(*) FROM used_transactions WHERE granted_at > ?", (since,)
        ).fetchone()
        if everyone >= config.GRANT_MAX_PER_DAY:
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

    Without this a failed send would still count against the address's
    allowance, with nothing to show for it.
    """
    with _lock:
        _db().execute("DELETE FROM used_transactions WHERE transaction_id = ?", (transaction_id,))
        _db().commit()
