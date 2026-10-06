"""The chain's slash debt tree (zk/debt), for rebuilding its root.

An indexed (sorted) tree on the depth-32 Poseidon2 Merkle tree
(merkle.SparseTree) with one row per slashed private redelegation (chain
ORCHARD_DESIGN.md section 20.6). Leaf i holds one row and its successor in
numeric key order:

    leaf = debt_leaf(key, next_key, next_index, retained)    H(TAG_DEBTL, ...)

key is the move key (the redelegation's credit nullifier), retained what its
exposure is still worth. next_key = 0 (next_index 0) for the largest key.
Leaf 0 is the sentinel (key 0, retained 0), written by the first row, so the
first row is leaf 1. A new key appends at the next index and repoints its
predecessor (the low leaf); an existing key's leaf is rewritten in place with
its new retained (it only falls). Rows are never removed. A tree with no row
has EMPTY_ROOT (the sentinel alone) and size 0.

Leaf positions are insertion order, so a tree is rebuilt from its rows in
leaf-index order, each with its latest retained (zk/debt Rebuild).
tests/test_zk.py pins this to vectors from the Go code.
"""
import bisect

from .merkle import CAPACITY, SparseTree
from .poseidon2 import P
from .privacy import debt_leaf


class DebtTree:
    def __init__(self) -> None:
        self.tree = SparseTree()
        self._sorted: list[int] = []        # keys, ascending
        self._index: dict[int, int] = {}    # key -> leaf index
        self._retained: dict[int, int] = {}

    @property
    def size(self) -> int:
        """Leaf count, the sentinel included (0 before the first row)."""
        return self.tree.size

    def _leaf(self, key: int) -> int:
        """key's full leaf (0: the sentinel) from the current order."""
        pos = bisect.bisect_right(self._sorted, key)
        if pos < len(self._sorted):
            nk = self._sorted[pos]
            nxt, ni = nk, self._index[nk]
        else:
            nxt, ni = 0, 0
        return debt_leaf(key, nxt, ni, self._retained.get(key, 0))

    def set(self, key: int, retained: int) -> int:
        """Records key's retained (a new row, or its leaf rewritten); returns its leaf index."""
        if not 0 < key < P:
            raise ValueError("0 is the sentinel and keys must be canonical field elements")
        if not 0 <= retained < 1 << 64:
            raise ValueError("retained must be a u64")
        if key in self._index:
            idx = self._index[key]
            self._retained[key] = retained
            self.tree.update(idx, self._leaf(key))
            return idx
        if self.tree.size == 0:
            self.tree.append(debt_leaf(0, 0, 0, 0))
        if self.tree.size >= CAPACITY:
            raise ValueError("tree full")
        pos = bisect.bisect_left(self._sorted, key)
        idx = self.tree.size
        self._retained[key] = retained
        self._sorted.insert(pos, key)
        self._index[key] = idx
        self.tree.append(self._leaf(key))
        low = self._sorted[pos - 1] if pos else 0
        self.tree.update(self._index[low] if pos else 0, self._leaf(low))
        return idx

    def root(self) -> int:
        if self.tree.size == 0:
            return EMPTY_ROOT
        return self.tree.root()


def _empty_root() -> int:
    t = SparseTree()
    t.append(debt_leaf(0, 0, 0, 0))
    return t.root()


EMPTY_ROOT = _empty_root()
