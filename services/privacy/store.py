"""The privacy index: SQLite, one transaction per block.

Every block is applied whole or not at all, together with the height it
brings the index to, so a crash at any point resumes cleanly at the next
block and applying a block twice is a no-op. Blocks must arrive in order.

Applying checks what the chain guarantees, and refuses the block (halting
the indexer) when it does not hold, rather than serving a tree that cannot
match the chain's roots:

- note positions are exactly the next ones, in order;
- an identity leaf event either appends at the next index or zeroes one
  already written;
- a nullifier is never seen twice;
- a root event's tree_size equals the indexed size at that block.

The stake note tree (x/shieldedstaking) is held the same way, in its own
tables: stake note positions in sequence, stake nullifiers once, stake root
sizes equal to the indexed stake tree.

Readers (the API) use their own connections; WAL keeps them from blocking the
writer.
"""
import sqlite3
import threading
from contextlib import contextmanager

from .events import ZERO32, BlockDelta

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash   TEXT NOT NULL,
    time   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    position   INTEGER PRIMARY KEY,
    cm         BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    height     INTEGER NOT NULL,
    amount     TEXT
);
CREATE INDEX IF NOT EXISTS notes_by_height ON notes (height);
CREATE TABLE IF NOT EXISTS nullifiers (
    seq    INTEGER PRIMARY KEY,
    nf     BLOB NOT NULL UNIQUE,
    height INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nullifiers_by_height ON nullifiers (height, seq);
CREATE TABLE IF NOT EXISTS identity_leaves (
    idx           INTEGER PRIMARY KEY,
    leaf          BLOB NOT NULL,
    height        INTEGER NOT NULL,
    zeroed_height INTEGER
);
CREATE TABLE IF NOT EXISTS identity_writes (
    seq    INTEGER PRIMARY KEY,
    idx    INTEGER NOT NULL,
    leaf   BLOB NOT NULL,
    height INTEGER NOT NULL,
    zeroed INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_zeroings ON identity_writes (zeroed, height, seq);
CREATE TABLE IF NOT EXISTS note_roots (
    height    INTEGER PRIMARY KEY,
    root      BLOB NOT NULL,
    tree_size INTEGER NOT NULL,
    time      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_roots (
    height    INTEGER PRIMARY KEY,
    root      BLOB NOT NULL,
    tree_size INTEGER NOT NULL,
    time      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rates (
    height      INTEGER NOT NULL,
    validator   TEXT NOT NULL,
    epoch       INTEGER,
    rate        TEXT NOT NULL,
    supply      TEXT NOT NULL,
    rewards     TEXT NOT NULL,
    delegated   TEXT NOT NULL,
    undelegated TEXT NOT NULL,
    PRIMARY KEY (height, validator)
);
CREATE TABLE IF NOT EXISTS stake_notes (
    position   INTEGER PRIMARY KEY,
    cm         BLOB NOT NULL,
    height     INTEGER NOT NULL,
    ciphertext BLOB,            -- every note (minted: blind stake ciphertext); NULL only in pre-fced976 indexes
    denom      TEXT,            -- minted by the chain: denom, amount, spc public
    amount     TEXT,
    spc        BLOB
);
CREATE INDEX IF NOT EXISTS stake_notes_by_height ON stake_notes (height);
CREATE TABLE IF NOT EXISTS stake_nullifiers (
    seq    INTEGER PRIMARY KEY,
    nf     BLOB NOT NULL UNIQUE,
    height INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS stake_nullifiers_by_height ON stake_nullifiers (height, seq);
CREATE TABLE IF NOT EXISTS stake_roots (
    height    INTEGER PRIMARY KEY,
    root      BLOB NOT NULL,
    tree_size INTEGER NOT NULL,
    time      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rates_by_epoch ON rates (epoch, validator);
CREATE INDEX IF NOT EXISTS rates_by_validator ON rates (validator, height);
"""


class Inconsistent(Exception):
    """A block contradicts what is indexed. The index stops rather than diverge."""


def connect(path: str, *, readonly: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    # Readers create the schema too, so an API started before the indexer
    # serves empty streams rather than errors.
    conn.executescript(SCHEMA)
    if readonly:
        conn.execute("PRAGMA query_only=1")
    return conn


def stake_counts(c: sqlite3.Connection) -> tuple[int, int]:
    """(stake notes, stake nullifiers) indexed."""
    (n,) = c.execute("SELECT COALESCE(MAX(position) + 1, 0) FROM stake_notes").fetchone()
    (f,) = c.execute("SELECT COUNT(*) FROM stake_nullifiers").fetchone()
    return n, f


def counts(c: sqlite3.Connection) -> tuple[int, int, int]:
    """(notes, identity leaves, nullifiers) indexed."""
    (n,) = c.execute("SELECT COALESCE(MAX(position) + 1, 0) FROM notes").fetchone()
    (i,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM identity_leaves").fetchone()
    (f,) = c.execute("SELECT COUNT(*) FROM nullifiers").fetchone()
    return n, i, f


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = connect(path)
        self._lock = threading.Lock()

    def close(self) -> None:
        self.conn.close()

    # --- meta -------------------------------------------------------------

    def meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, str(value)))

    def last_height(self) -> int:
        v = self.meta("last_height")
        return int(v) if v is not None else 0

    def block_hash(self, height: int) -> str | None:
        row = self.conn.execute("SELECT hash FROM blocks WHERE height = ?", (height,)).fetchone()
        return row[0] if row else None

    def counts(self) -> tuple[int, int, int]:
        return counts(self.conn)

    def stake_counts(self) -> tuple[int, int]:
        return stake_counts(self.conn)

    # --- writing ----------------------------------------------------------

    @contextmanager
    def _tx(self):
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def apply(self, d: BlockDelta) -> bool:
        """Applies one block. False (and nothing written) if already applied."""
        with self._tx() as c:
            last = int((c.execute("SELECT value FROM meta WHERE key = 'last_height'").fetchone() or [0])[0])
            if last and d.height <= last:
                return False
            if last and d.height != last + 1:
                raise Inconsistent(f"block {d.height} after {last}: blocks must be applied in order")
            (notes,) = c.execute("SELECT COALESCE(MAX(position) + 1, 0) FROM notes").fetchone()
            (ids,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM identity_leaves").fetchone()
            (stakes,) = c.execute("SELECT COALESCE(MAX(position) + 1, 0) FROM stake_notes").fetchone()

            c.execute("INSERT INTO blocks (height, hash, time) VALUES (?, ?, ?)", (d.height, d.hash, d.time))

            for n in d.notes:
                if n.position != notes:
                    raise Inconsistent(
                        f"block {d.height}: note at position {n.position}, expected {notes}"
                        + (" (history before the start height is missing)" if not last and notes == 0 else "")
                    )
                c.execute("INSERT INTO notes (position, cm, ciphertext, height, amount) VALUES (?, ?, ?, ?, ?)",
                          (n.position, n.cm, n.ciphertext, d.height, n.amount))
                notes += 1

            for nf in d.nullifiers:
                try:
                    c.execute("INSERT INTO nullifiers (nf, height) VALUES (?, ?)", (nf, d.height))
                except sqlite3.IntegrityError as exc:
                    raise Inconsistent(f"block {d.height}: nullifier {nf.hex()} spent twice") from exc

            for w in d.identity:
                zero = w.leaf == ZERO32
                if w.index == ids:
                    # An append. (A zero leaf is never appended; if one were,
                    # it is still just an empty slot.)
                    c.execute("INSERT INTO identity_leaves (idx, leaf, height, zeroed_height) VALUES (?, ?, ?, ?)",
                              (w.index, w.leaf, d.height, d.height if zero else None))
                    ids += 1
                    zeroing = False
                elif w.index < ids and zero:
                    c.execute("UPDATE identity_leaves SET zeroed_height = COALESCE(zeroed_height, ?) WHERE idx = ?",
                              (d.height, w.index))
                    zeroing = True
                elif w.index < ids:
                    raise Inconsistent(f"block {d.height}: identity leaf {w.index} rewritten with a non-zero value")
                else:
                    raise Inconsistent(
                        f"block {d.height}: identity leaf at index {w.index}, expected {ids}"
                        + (" (history before the start height is missing)" if not last and ids == 0 else "")
                    )
                c.execute("INSERT INTO identity_writes (idx, leaf, height, zeroed) VALUES (?, ?, ?, ?)",
                          (w.index, w.leaf, d.height, 1 if zeroing else 0))

            if d.note_root is not None:
                if d.note_root.tree_size != notes:
                    raise Inconsistent(f"block {d.height}: note root at size {d.note_root.tree_size}, indexed {notes}")
                c.execute("INSERT INTO note_roots (height, root, tree_size, time) VALUES (?, ?, ?, ?)",
                          (d.height, d.note_root.root, d.note_root.tree_size, d.time))
            if d.identity_root is not None:
                if d.identity_root.tree_size != ids:
                    raise Inconsistent(f"block {d.height}: identity root at size {d.identity_root.tree_size}, indexed {ids}")
                c.execute("INSERT INTO identity_roots (height, root, tree_size, time) VALUES (?, ?, ?, ?)",
                          (d.height, d.identity_root.root, d.identity_root.tree_size, d.time))

            for n in d.stake_notes:
                if n.position != stakes:
                    raise Inconsistent(
                        f"block {d.height}: stake note at position {n.position}, expected {stakes}"
                        + (" (history before the start height is missing)" if not last and stakes == 0 else "")
                    )
                c.execute("INSERT INTO stake_notes (position, cm, height, ciphertext, denom, amount, spc)"
                          " VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (n.position, n.cm, d.height, n.ciphertext, n.denom, n.amount, n.spc))
                stakes += 1

            for nf in d.stake_nullifiers:
                try:
                    c.execute("INSERT INTO stake_nullifiers (nf, height) VALUES (?, ?)", (nf, d.height))
                except sqlite3.IntegrityError as exc:
                    raise Inconsistent(f"block {d.height}: stake nullifier {nf.hex()} spent twice") from exc

            if d.stake_root is not None:
                if d.stake_root.tree_size != stakes:
                    raise Inconsistent(f"block {d.height}: stake root at size {d.stake_root.tree_size}, indexed {stakes}")
                c.execute("INSERT INTO stake_roots (height, root, tree_size, time) VALUES (?, ?, ?, ?)",
                          (d.height, d.stake_root.root, d.stake_root.tree_size, d.time))

            # A validator event with no epoch event after it in its block is
            # a book of the epoch whose sweep is still going (past 200
            # validators the sweep spans blocks, x/shieldedstaking
            # EpochValidatorLimit): the epoch the last epoch event ended.
            # (An epoch end that failed outright before its event, retried
            # next block, is labelled the same way; the chain logs that as
            # a shieldedstaking_epoch_failure.)
            row = c.execute("SELECT value FROM meta WHERE key = 'sweep_epoch'").fetchone()
            sweep = d.epoch_ended if d.epoch_ended is not None else (int(row[0]) if row else None)
            for r in d.rates:
                c.execute(
                    "INSERT OR REPLACE INTO rates (height, validator, epoch, rate, supply, rewards, delegated, undelegated)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (d.height, r.validator, r.epoch if r.epoch is not None else sweep,
                     r.rate, r.supply, r.rewards, r.delegated, r.undelegated),
                )
            if d.epoch_ended is not None:
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('sweep_epoch', ?)", (str(d.epoch_ended),))

            if not last:
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('start_height', ?)", (str(d.height),))
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_height', ?)", (str(d.height),))
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_time', ?)", (str(d.time),))
        return True
