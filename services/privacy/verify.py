"""Rebuilds the note, identity, stake, stake nullifier and slash debt trees from the index and checks their roots.

Two checks, the second optional:

1. Against the index's own root events. The trees are replayed from the
   indexed notes and identity writes with the Python Poseidon2
   (services/zk), and the root after each block that recorded one is compared
   with the root the chain emitted for it. By default only the latest root of
   each tree is checked (one bulk rebuild, ~2 hashes a leaf); all_roots checks
   every recorded root (up to 32 hashes per changed leaf per block). The
   stake tree (x/shieldedstaking: same depth-32 Poseidon2 tree, leaves the
   stake commitments; every one a stake proof output since chain dff3a9b,
   none with a public value) is replayed the same way. The slash debt tree
   (zk/debt: an indexed tree, leaf H(TAG_DEBTL, key, next_key, next_index,
   retained), rows rewritten in place) is replayed from every debt row
   write in order, each write's leaf index and the root the chain emitted
   after it checked, always (rows are only written by slashes, so few). The
   stake nullifier
   tree (zk/indexed: an indexed tree whose leaves are in insertion order) is
   rebuilt from the nullifiers in leaf-index order and its root checked at
   every proposal snapshot's nf_size against the snapshot's nf_root (the
   chain emits no per-block nullifier root; snapshots are where it is
   published), always, not only with all_roots. Every open note (the
   referral note, published with its opening) is checked the same way:
   cm == H(TAG_CM, AssetID(denom), amount, PC(owner_pk, rho, rcm)), exactly
   what its owner's wallet recomputes from the row.
2. Against the chain itself, at the index's synced height, over CometBFT
   abci_query: x/shielded Query/Tree (size, current root, latest anchor),
   x/personhood Query/IdentityTree (size, latest root) and x/shieldedstaking
   Query/StakeTree (size, latest root), Query/StakeNullifierTree (size,
   current root) and Query/DebtTree (every row, in leaf order with its
   retained, the size and the root). This is what proves
   the index — and so every wallet syncing from it — sees the chain's trees.
"""
import re
import sqlite3
from dataclasses import dataclass, field

from services.zk import privacy
from services.zk.debt import DebtTree
from services.zk.indexed import IndexedTree
from services.zk.merkle import SparseTree

from .rpc import CometRPC, proto_fields

NOTE_TREE_QUERY = "/earth.shielded.v1.Query/Tree"
IDENTITY_TREE_QUERY = "/earth.personhood.v1.Query/IdentityTree"
STAKE_TREE_QUERY = "/earth.shieldedstaking.v1.Query/StakeTree"
STAKE_NF_TREE_QUERY = "/earth.shieldedstaking.v1.Query/StakeNullifierTree"
STAKE_NF_TREE_REQUEST = b"\x10\x01"  # limit 1: only size and roots are read
DEBT_TREE_QUERY = "/earth.shieldedstaking.v1.Query/DebtTree"
DEBT_PAGE = 1000  # Query/DebtTree's own cap
_COIN = re.compile(r"([0-9]+)([a-zA-Z][a-zA-Z0-9/:._-]*)")


@dataclass
class Report:
    synced_height: int = 0
    note_size: int = 0
    identity_size: int = 0
    note_root: bytes | None = None
    identity_root: bytes | None = None
    stake_size: int = 0
    stake_root: bytes | None = None
    debt_size: int = 0
    debt_root: bytes | None = None
    debt_writes_checked: int = 0
    open_notes_checked: int = 0
    stake_nf_size: int = 0
    stake_nf_root: bytes | None = None
    snapshots_checked: int = 0
    roots_checked: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _b(v: int) -> bytes:
    return v.to_bytes(32, "big")


def rebuild(conn: sqlite3.Connection, all_roots: bool = False) -> Report:
    rep = Report()
    row = conn.execute("SELECT value FROM meta WHERE key = 'last_height'").fetchone()
    rep.synced_height = int(row[0]) if row else 0

    # --- note tree ---
    roots = conn.execute("SELECT height, root, tree_size FROM note_roots ORDER BY height").fetchall()
    if not all_roots:
        roots = roots[-1:]
    t = SparseTree()
    notes = conn.execute("SELECT position, cm FROM notes ORDER BY position")
    pending = notes.fetchone()
    for height, root, size in roots:
        while pending is not None and pending[0] < size:
            t.append(int.from_bytes(pending[1], "big"))
            pending = notes.fetchone()
        got = _b(t.root())
        rep.roots_checked += 1
        if t.size != size or got != root:
            rep.errors.append(f"note root at height {height} (size {size}): rebuilt {got.hex()} at size {t.size}, chain emitted {root.hex()}")
    while pending is not None:
        t.append(int.from_bytes(pending[1], "big"))
        pending = notes.fetchone()
    rep.note_size = t.size
    rep.note_root = _b(t.root())
    for pos, cm, amount, opk, rho, rcm in conn.execute(
            "SELECT position, cm, amount, owner_pk, rho, rcm FROM notes WHERE owner_pk IS NOT NULL ORDER BY position"):
        rep.open_notes_checked += 1
        m = _COIN.fullmatch(amount or "")
        if m is None:
            rep.errors.append(f"open note {pos}: amount {amount!r} is not a coin")
            continue
        pc_ = privacy.pc(*(int.from_bytes(v, "big") for v in (opk, rho, rcm)))
        want = privacy.cm(privacy.asset_id(m[2]), int(m[1]), pc_)
        if _b(want) != cm:
            rep.errors.append(f"open note {pos}: commitment {cm.hex()} is not H(TAG_CM, {m[2]}, {m[1]}, "
                              f"PC(owner_pk, rho, rcm)), {_b(want).hex()}")

    # --- identity tree ---
    roots = conn.execute("SELECT height, root, tree_size FROM identity_roots ORDER BY height").fetchall()
    if not all_roots:
        roots = roots[-1:]
    it = SparseTree()
    writes = conn.execute("SELECT idx, leaf, height FROM identity_writes ORDER BY seq")
    pending = writes.fetchone()

    def apply(w) -> None:
        idx, leaf, _ = w
        v = int.from_bytes(leaf, "big")
        if idx == it.size:
            it.append(v)
        else:
            it.update(idx, v)

    for height, root, size in roots:
        while pending is not None and pending[2] <= height:
            apply(pending)
            pending = writes.fetchone()
        got = _b(it.root())
        rep.roots_checked += 1
        if it.size != size or got != root:
            rep.errors.append(f"identity root at height {height} (size {size}): rebuilt {got.hex()} at size {it.size}, chain emitted {root.hex()}")
    while pending is not None:
        apply(pending)
        pending = writes.fetchone()
    rep.identity_size = it.size
    rep.identity_root = _b(it.root())

    # --- stake tree ---
    roots = conn.execute("SELECT height, root, tree_size FROM stake_roots ORDER BY height").fetchall()
    if not all_roots:
        roots = roots[-1:]
    st = SparseTree()
    stakes = conn.execute("SELECT position, cm FROM stake_notes ORDER BY position")

    def stake_append(row) -> None:
        st.append(int.from_bytes(row[1], "big"))

    pending = stakes.fetchone()
    for height, root, size in roots:
        while pending is not None and pending[0] < size:
            stake_append(pending)
            pending = stakes.fetchone()
        got = _b(st.root())
        rep.roots_checked += 1
        if st.size != size or got != root:
            rep.errors.append(f"stake root at height {height} (size {size}): rebuilt {got.hex()} at size {st.size}, chain emitted {root.hex()}")
    while pending is not None:
        stake_append(pending)
        pending = stakes.fetchone()
    rep.stake_size = st.size
    # The empty tree has a root too (ZERO[32]): the chain records it at the
    # first block (dff3a9b), so a first delegation's padding proves against it.
    rep.stake_root = _b(st.root())

    # --- slash debt tree (indexed; rows rewritten in place) ---
    dt = DebtTree()
    for seq, idx, key, retained, height, root in conn.execute(
            "SELECT seq, idx, key, retained, height, root FROM debt_writes ORDER BY seq"):
        try:
            got = dt.set(int.from_bytes(key, "big"), retained)
        except ValueError as exc:
            rep.errors.append(f"debt row {key.hex()} (height {height}): {exc}")
            continue
        rep.debt_writes_checked += 1
        if got != idx:
            rep.errors.append(f"debt row {key.hex()} (height {height}): indexed at leaf {idx}, rebuilt at {got}")
        r = _b(dt.root())
        if r != root:
            rep.errors.append(f"debt row {key.hex()} (height {height}): chain emitted root {root.hex()}, rebuilt {r.hex()}")
    for idx, key, retained in conn.execute("SELECT idx, key, retained FROM debt_rows ORDER BY idx"):
        if dt._index.get(int.from_bytes(key, "big")) != idx or dt._retained.get(int.from_bytes(key, "big")) != retained:
            rep.errors.append(f"debt row {key.hex()} at leaf {idx} (retained {retained}) is not its last write")
    rep.debt_size = dt.size
    rep.debt_root = _b(dt.root())

    # --- stake nullifier tree (indexed; leaf order is insertion order) ---
    # Every proposal snapshot names the tree's root at a size (the first
    # nf_size - 1 values, as a wallet rebuilds it to prove a vote): checked
    # at each, smallest first, then the whole tree.
    snaps = conn.execute("SELECT proposal_id, height, nf_root, nf_size, root, tree_size FROM stake_snapshots"
                         " ORDER BY nf_size, proposal_id").fetchall()
    nt = IndexedTree()
    values = conn.execute("SELECT idx, nf FROM stake_nullifiers ORDER BY idx")
    pending = values.fetchone()

    def nf_insert(row) -> None:
        idx, nf = row
        got = nt.insert(int.from_bytes(nf, "big"))
        if got != idx:
            rep.errors.append(f"stake nullifier {nf.hex()}: indexed at leaf {idx}, rebuilt at {got}")

    for pid, height, nf_root, nf_size, _, _ in snaps:
        while pending is not None and nt.size < nf_size:
            nf_insert(pending)
            pending = values.fetchone()
        got = _b(nt.root())
        rep.snapshots_checked += 1
        if nt.size != nf_size or got != nf_root:
            rep.errors.append(f"proposal {pid} snapshot (height {height}): nullifier tree of size {nf_size} has root "
                              f"{nf_root.hex()}, rebuilt {got.hex()} at size {nt.size}")
    while pending is not None:
        nf_insert(pending)
        pending = values.fetchone()
    rep.stake_nf_size = nt.size
    rep.stake_nf_root = _b(nt.root())

    # A snapshot's stake note root is one the chain recorded: when the index
    # holds that root event, its size must match.
    for pid, height, _, _, root, size in snaps:
        if not root:
            continue
        row = conn.execute("SELECT tree_size FROM stake_roots WHERE root = ? ORDER BY height DESC LIMIT 1", (root,)).fetchone()
        if row is not None and row[0] != size:
            rep.errors.append(f"proposal {pid} snapshot (height {height}): stake root {root.hex()} at size {size}, "
                              f"recorded at size {row[0]}")
    return rep


async def check_chain(rep: Report, rpc: CometRPC, conn: sqlite3.Connection | None = None) -> None:
    """Compares the rebuilt trees with the chain's own at the synced height
    (with conn, the index's debt rows with the chain's too)."""
    h = rep.synced_height
    if not h:
        rep.errors.append("the index is empty")
        return
    tree = proto_fields(await rpc.abci_query(NOTE_TREE_QUERY, height=h))
    size = (tree.get(1) or [0])[-1]
    current = bytes.fromhex((tree.get(2) or [b""])[-1].decode() or "")
    anchor = proto_fields((tree.get(3) or [b""])[-1])
    anchor_root = (anchor.get(1) or [b""])[-1]
    if size != rep.note_size:
        rep.errors.append(f"note tree: chain size {size} at height {h}, index {rep.note_size}")
    if current and current != rep.note_root:
        rep.errors.append(f"note tree: chain root {current.hex()} at height {h}, rebuilt {rep.note_root.hex()}")
    if anchor_root and anchor_root != rep.note_root:
        rep.errors.append(f"note tree: chain anchor {anchor_root.hex()} at height {h}, rebuilt {rep.note_root.hex()}")

    ident = proto_fields(await rpc.abci_query(IDENTITY_TREE_QUERY, height=h))
    isize = (ident.get(1) or [0])[-1]
    iroot = (ident.get(2) or [b""])[-1]
    if isize != rep.identity_size:
        rep.errors.append(f"identity tree: chain size {isize} at height {h}, index {rep.identity_size}")
    if iroot and iroot != rep.identity_root:
        rep.errors.append(f"identity tree: chain root {iroot.hex()} at height {h}, rebuilt {rep.identity_root.hex()}")

    stake = proto_fields(await rpc.abci_query(STAKE_TREE_QUERY, height=h))
    ssize = (stake.get(1) or [0])[-1]
    sroot = (stake.get(2) or [b""])[-1]
    if ssize != rep.stake_size:
        rep.errors.append(f"stake tree: chain size {ssize} at height {h}, index {rep.stake_size}")
    if sroot and sroot != rep.stake_root:
        rep.errors.append(f"stake tree: chain root {sroot.hex()} at height {h}, rebuilt {(rep.stake_root or b'').hex()}")

    nft = proto_fields(await rpc.abci_query(STAKE_NF_TREE_QUERY, STAKE_NF_TREE_REQUEST, height=h))
    nsize = (nft.get(2) or [0])[-1]
    nroot = (nft.get(3) or [b""])[-1]
    if nsize != rep.stake_nf_size:
        rep.errors.append(f"stake nullifier tree: chain size {nsize} at height {h}, index {rep.stake_nf_size}")
    if nroot and nroot != rep.stake_nf_root:
        rep.errors.append(f"stake nullifier tree: chain root {nroot.hex()} at height {h}, rebuilt {(rep.stake_nf_root or b'').hex()}")

    await check_debt_rows(rep, rpc, conn)


def _debt_request(start: int, limit: int) -> bytes:
    """QueryDebtTreeRequest {start 1, limit 2}: rows from leaf start+1."""
    def varint(v: int) -> bytes:
        out = bytearray()
        while True:
            b, v = v & 0x7F, v >> 7
            out.append(b | 0x80 if v else b)
            if not v:
                return bytes(out)
    return (b"\x08" + varint(start) if start else b"") + b"\x10" + varint(limit)


async def check_debt_rows(rep: Report, rpc: CometRPC, conn: sqlite3.Connection | None) -> None:
    """Query/DebtTree at the synced height: size and root against the rebuilt
    tree, and (with conn) every row, in leaf order, against the index's."""
    h = rep.synced_height
    first = proto_fields(await rpc.abci_query(DEBT_TREE_QUERY, _debt_request(0, DEBT_PAGE), height=h))
    size = (first.get(2) or [0])[-1]
    root = (first.get(3) or [b""])[-1]
    if size != rep.debt_size:
        rep.errors.append(f"slash debt tree: chain size {size} at height {h}, index {rep.debt_size}")
    if root != rep.debt_root:
        rep.errors.append(f"slash debt tree: chain root {root.hex()} at height {h}, rebuilt {(rep.debt_root or b'').hex()}")
    if conn is None:
        return
    chain_rows: list[tuple[bytes, int]] = []
    page = first
    while True:
        rows = page.get(1) or []
        for r in rows:
            f = proto_fields(r)
            chain_rows.append(((f.get(1) or [b""])[-1], (f.get(2) or [0])[-1]))
        if len(rows) < DEBT_PAGE or len(chain_rows) >= max(size - 1, 0):
            break
        page = proto_fields(await rpc.abci_query(DEBT_TREE_QUERY, _debt_request(len(chain_rows), DEBT_PAGE), height=h))
    have = [(k, r) for k, r in conn.execute("SELECT key, retained FROM debt_rows ORDER BY idx")]
    if chain_rows != have:
        for i, (c, x) in enumerate(zip(chain_rows, have)):
            if c != x:
                rep.errors.append(f"slash debt row at leaf {i + 1}: chain {c[0].hex()} retained {c[1]}, "
                                  f"index {x[0].hex()} retained {x[1]}")
                break
        else:
            rep.errors.append(f"slash debt rows: chain {len(chain_rows)}, index {len(have)}")
