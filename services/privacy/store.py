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
tables: stake note positions in sequence, stake root sizes equal to the
indexed stake tree. Stake nullifiers carry their leaf index in the stake
nullifier tree, which must be exactly the next one (1, 2, 3, ...), each
nullifier once; a proposal snapshot is recorded once and never names a tree
size past what is indexed.

The handle directory is not built from events: it is a snapshot of the
chain's Handles query at one height (services/privacy/handles), replaced
whole by replace_handles. A block with a handle event records its height
(meta handles_changed_height) so the indexer knows the snapshot is behind.

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
-- The stake nullifier tree's values: idx is the leaf index the chain gave
-- each (1, 2, 3, ... in insertion order; leaf 0 is the sentinel).
CREATE TABLE IF NOT EXISTS stake_nullifiers (
    idx    INTEGER PRIMARY KEY,
    nf     BLOB NOT NULL UNIQUE,
    height INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS stake_nullifiers_by_height ON stake_nullifiers (height, idx);
CREATE TABLE IF NOT EXISTS stake_snapshots (
    proposal_id INTEGER PRIMARY KEY,
    height      INTEGER NOT NULL,
    root        BLOB NOT NULL,      -- empty when the stake note tree had no root yet
    tree_size   INTEGER NOT NULL,
    nf_root     BLOB NOT NULL,
    nf_size     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS stake_snapshots_by_height ON stake_snapshots (height, proposal_id);
CREATE TABLE IF NOT EXISTS stake_roots (
    height    INTEGER PRIMARY KEY,
    root      BLOB NOT NULL,
    tree_size INTEGER NOT NULL,
    time      INTEGER NOT NULL
);
-- The handle directory at meta handles_height (block time handles_time), in
-- handle order; idx is the row's place in it (0, 1, 2, ...).
CREATE TABLE IF NOT EXISTS handles (
    idx           INTEGER PRIMARY KEY,
    handle        TEXT NOT NULL UNIQUE,
    address       TEXT NOT NULL,
    status        TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    renewal_until INTEGER NOT NULL
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
    cols = [r[1] for r in conn.execute("PRAGMA table_info(stake_nullifiers)")]
    if cols and "idx" not in cols:
        conn.close()
        raise RuntimeError(f"{path} predates the stake nullifier tree (stake nullifiers without leaf indexes, "
                           f"from a chain before it): wipe INDEX_DB and index again")
    # Readers create the schema too, so an API started before the indexer
    # serves empty streams rather than errors.
    conn.executescript(SCHEMA)
    if readonly:
        conn.execute("PRAGMA query_only=1")
    return conn


def stake_nf_size(c: sqlite3.Connection) -> int:
    """The stake nullifier tree's leaf count as the chain reports it: the
    values plus the sentinel, 0 before the first insert."""
    (n,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM stake_nullifiers").fetchone()
    return n


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

    def stake_nf_size(self) -> int:
        return stake_nf_size(self.conn)

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

            # Leaf indexes exactly in sequence from 1 (leaf 0 is the
            # sentinel): wallets rebuild the indexed tree in this order, so a
            # gap or a repeat would give every later root wrongly.
            (nf_next,) = c.execute("SELECT COALESCE(MAX(idx) + 1, 1) FROM stake_nullifiers").fetchone()
            for n in d.stake_nullifiers:
                if n.index != nf_next:
                    raise Inconsistent(
                        f"block {d.height}: stake nullifier {n.nf.hex()} at leaf {n.index}, expected {nf_next}"
                        + (" (history before the start height is missing)" if not last and nf_next == 1 else "")
                    )
                try:
                    c.execute("INSERT INTO stake_nullifiers (idx, nf, height) VALUES (?, ?, ?)", (n.index, n.nf, d.height))
                except sqlite3.IntegrityError as exc:
                    raise Inconsistent(f"block {d.height}: stake nullifier {n.nf.hex()} spent twice") from exc
                nf_next += 1

            for sn in d.snapshots:
                # A snapshot takes the nullifier tree as recorded at the end
                # of an earlier block, so it can never be past what is indexed.
                if sn.nf_size > nf_next or sn.nf_size == 1:
                    raise Inconsistent(f"block {d.height}: proposal {sn.proposal_id} snapshot at nullifier tree size "
                                       f"{sn.nf_size}, indexed {nf_next if nf_next > 1 else 0}")
                if sn.tree_size > stakes:
                    raise Inconsistent(f"block {d.height}: proposal {sn.proposal_id} snapshot at stake tree size "
                                       f"{sn.tree_size}, indexed {stakes}")
                try:
                    c.execute("INSERT INTO stake_snapshots (proposal_id, height, root, tree_size, nf_root, nf_size)"
                              " VALUES (?, ?, ?, ?, ?, ?)",
                              (sn.proposal_id, d.height, sn.root, sn.tree_size, sn.nf_root, sn.nf_size))
                except sqlite3.IntegrityError as exc:
                    raise Inconsistent(f"block {d.height}: proposal {sn.proposal_id} snapshotted twice") from exc

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

            if d.handles_changed:
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('handles_changed_height', ?)", (str(d.height),))

            if not last:
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('start_height', ?)", (str(d.height),))
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_height', ?)", (str(d.height),))
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_time', ?)", (str(d.time),))
        return True

    def handles_due(self, max_age: int) -> bool:
        """Whether the handle snapshot is behind the indexed chain: never taken,
        older than a handle event, past a status change by time, or older
        than max_age seconds of block time."""
        h, last = self.meta("handles_height"), self.last_height()
        if not last:
            return False
        if h is None:
            return True
        if int(h) >= last:
            return False
        if int(self.meta("handles_changed_height") or 0) > int(h):
            return True
        now = int(self.meta("last_time") or 0)
        nxt = self.meta("handles_next_change")
        if nxt is not None and now >= int(nxt):
            return True
        return now - int(self.meta("handles_time") or 0) >= max_age

    def replace_handles(self, height: int, time: int, entries, next_change: int | None) -> None:
        """Replaces the handle directory with entries (in handle order), the chain's at height."""
        with self._tx() as c:
            c.execute("DELETE FROM handles")
            c.executemany("INSERT INTO handles (idx, handle, address, status, expires_at, renewal_until)"
                          " VALUES (?, ?, ?, ?, ?, ?)",
                          [(i, e.handle, e.address, e.status, e.expires_at, e.renewal_until)
                           for i, e in enumerate(entries)])
            for k, v in (("handles_height", height), ("handles_time", time)):
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (k, str(v)))
            if next_change is None:
                c.execute("DELETE FROM meta WHERE key = 'handles_next_change'")
            else:
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('handles_next_change', ?)",
                          (str(next_change),))
