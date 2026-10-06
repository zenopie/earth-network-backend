"""The chain's stake nullifier tree (zk/indexed), for rebuilding its root.

An indexed (sorted, Aztec-style) tree on the depth-32 Poseidon2 Merkle tree
(merkle.SparseTree). Leaf i holds one inserted value and its successor in
numeric order:

    leaf = nf_leaf(value, next_value, next_index)    H(TAG_SNFL, ...)

next_value = 0 (next_index 0) for the largest value. Leaf 0 is the sentinel
(value 0), written by the first insert, so the first value is leaf 1. Inserting
v appends (v, succ(v)) at the next index and repoints v's predecessor (the
"low leaf", the sentinel if none) at v. Values are canonical field elements
compared as integers. A tree nothing was inserted in has EMPTY_ROOT (the
sentinel alone) and size 0; after n inserts its size is n + 1.

The order of inserts determines the root (leaf positions are insertion order),
so a tree is rebuilt from the values in the order the chain inserted them.
tests/test_zk.py pins this to vectors from the Go code.
"""
import bisect

from .merkle import CAPACITY, SparseTree
from .privacy import nf_leaf
from .poseidon2 import P


class IndexedTree:
    def __init__(self) -> None:
        self.tree = SparseTree()
        self._sorted: list[int] = []        # inserted values, ascending
        self._index: dict[int, int] = {}    # value -> leaf index

    @property
    def size(self) -> int:
        """Leaf count, the sentinel included (0 before the first insert)."""
        return self.tree.size

    def _leaf(self, value: int, succ_pos: int) -> int:
        if succ_pos < len(self._sorted):
            nv = self._sorted[succ_pos]
            return nf_leaf(value, nv, self._index[nv])
        return nf_leaf(value, 0, 0)

    def insert(self, v: int) -> int:
        """Inserts v (nonzero, canonical, new) and returns its leaf index."""
        if not 0 < v < P:
            raise ValueError("0 is the sentinel and values must be canonical field elements")
        if v in self._index:
            raise ValueError(f"{v:064x} already in the tree")
        if self.tree.size == 0:
            self.tree.append(nf_leaf(0, 0, 0))
        if self.tree.size >= CAPACITY:
            raise ValueError("tree full")
        pos = bisect.bisect_left(self._sorted, v)
        idx = self.tree.size
        # v's own leaf points at its successor (what the low leaf pointed at).
        self.tree.append(self._leaf(v, pos))
        self._sorted.insert(pos, v)
        self._index[v] = idx
        # The low leaf now points at v.
        if pos == 0:
            low_value, low_index = 0, 0
        else:
            low_value = self._sorted[pos - 1]
            low_index = self._index[low_value]
        self.tree.update(low_index, nf_leaf(low_value, v, idx))
        return idx

    def root(self) -> int:
        if self.tree.size == 0:
            return EMPTY_ROOT
        return self.tree.root()


def _empty_root() -> int:
    t = SparseTree()
    t.append(nf_leaf(0, 0, 0))
    return t.root()


EMPTY_ROOT = _empty_root()
