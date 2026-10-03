"""Rebuilds the note, identity, stake and stake nullifier trees from the index and checks their roots.

Two checks, the second optional:

1. Against the index's own root events. The trees are replayed from the
   indexed notes and identity writes with the Python Poseidon2
   (services/zk), and the root after each block that recorded one is compared
   with the root the chain emitted for it. By default only the latest root of
   each tree is checked (one bulk rebuild, ~2 hashes a leaf); all_roots checks
   every recorded root (up to 32 hashes per changed leaf per block). The
   stake tree (x/shieldedstaking: same depth-32 Poseidon2 tree, leaves the
   stake commitments) is replayed the same way, and every stake note the
   chain minted is checked against its public denom, amount and stake pc:
   cm == H(TAG_STAKE, AssetID(denom), amount, spc). The stake nullifier
   tree (zk/indexed: an indexed tree whose leaves are in insertion order) is
   rebuilt from the nullifiers in leaf-index order and its root checked at
   every proposal snapshot's nf_size against the snapshot's nf_root (the
   chain emits no per-block nullifier root; snapshots are where it is
   published), always, not only with all_roots.
2. Against the chain itself, at the index's synced height, over CometBFT
   abci_query: x/shielded Query/Tree (size, current root, latest anchor),
   x/personhood Query/IdentityTree (size, latest root) and x/shieldedstaking
   Query/StakeTree (size, latest root), and Query/StakeNullifierTree (size,
   current root). This is what proves
   the index — and so every wallet syncing from it — sees the chain's trees.
"""
import sqlite3
from dataclasses import dataclass, field

from services.zk import privacy
from services.zk.indexed import IndexedTree
from services.zk.merkle import SparseTree

from .rpc import CometRPC, proto_fields

NOTE_TREE_QUERY = "/earth.shielded.v1.Query/Tree"
IDENTITY_TREE_QUERY = "/earth.personhood.v1.Query/IdentityTree"
STAKE_TREE_QUERY = "/earth.shieldedstaking.v1.Query/StakeTree"
STAKE_NF_TREE_QUERY = "/earth.shieldedstaking.v1.Query/StakeNullifierTree"
STAKE_NF_TREE_REQUEST = b"\x10\x01"  # limit 1: only size and roots are read


@dataclass
class Report:
    synced_height: int = 0
    note_size: int = 0
    identity_size: int = 0
    note_root: bytes | None = None
    identity_root: bytes | None = None
    stake_size: int = 0
    stake_root: bytes | None = None
    stake_minted_checked: int = 0
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
    stakes = conn.execute("SELECT position, cm, denom, amount, spc FROM stake_notes ORDER BY position")

    def stake_append(row) -> None:
        pos, cm, denom, amount, spc = row
        v = int.from_bytes(cm, "big")
        if denom is not None:
            want = privacy.stake_cm(privacy.asset_id(denom), int(amount), int.from_bytes(spc, "big"))
            rep.stake_minted_checked += 1
            if want != v:
                rep.errors.append(f"stake note {pos}: commitment {cm.hex()} is not H(TAG_STAKE, {denom}, {amount}, spc), {_b(want).hex()}")
        st.append(v)

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
    rep.stake_root = _b(st.root()) if st.size else None

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


async def check_chain(rep: Report, rpc: CometRPC) -> None:
    """Compares the rebuilt trees with the chain's own at the synced height."""
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
