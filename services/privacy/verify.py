"""Rebuilds the note and identity trees from the index and checks their roots.

Two checks, the second optional:

1. Against the index's own root events. The trees are replayed from the
   indexed notes and identity writes with the Python Poseidon2
   (services/zk), and the root after each block that recorded one is compared
   with the root the chain emitted for it. By default only the latest root of
   each tree is checked (one bulk rebuild, ~2 hashes a leaf); all_roots checks
   every recorded root (up to 32 hashes per changed leaf per block).
2. Against the chain itself, at the index's synced height, over CometBFT
   abci_query: x/shielded Query/Tree (size, current root, latest anchor) and
   x/personhood Query/IdentityTree (size, latest root). This is what proves
   the index — and so every wallet syncing from it — sees the chain's trees.
"""
import sqlite3
from dataclasses import dataclass, field

from services.zk.merkle import SparseTree

from .rpc import CometRPC, proto_fields

NOTE_TREE_QUERY = "/earth.shielded.v1.Query/Tree"
IDENTITY_TREE_QUERY = "/earth.personhood.v1.Query/IdentityTree"


@dataclass
class Report:
    synced_height: int = 0
    note_size: int = 0
    identity_size: int = 0
    note_root: bytes | None = None
    identity_root: bytes | None = None
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
