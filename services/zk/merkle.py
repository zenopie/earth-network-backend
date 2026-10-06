"""The chain's depth-32 Poseidon2 Merkle tree (zk/merkle), for rebuilding roots.

node = Poseidon2([left, right]); an empty leaf is 0 and ZERO[i+1] =
H(ZERO[i], ZERO[i]); bit i of a leaf's index set means the running node is the
right child at level i. A zeroed identity leaf is 0, the same as empty.

SparseTree keeps only written nodes and recomputes dirty paths in batches:
writing k leaves and then asking for the root costs about 2k hashes when the
leaves are adjacent (a bulk rebuild) and at most 32 per isolated leaf.
"""
from .poseidon2 import hash2

DEPTH = 32
CAPACITY = 1 << DEPTH

ZERO = [0]
for _ in range(DEPTH):
    ZERO.append(hash2(ZERO[-1], ZERO[-1]))


class SparseTree:
    def __init__(self) -> None:
        self.levels: list[dict[int, int]] = [dict() for _ in range(DEPTH + 1)]
        self.size = 0
        self._dirty: set[int] = set()

    def _node(self, level: int, index: int) -> int:
        return self.levels[level].get(index, ZERO[level])

    def append(self, leaf: int) -> int:
        if self.size >= CAPACITY:
            raise ValueError("tree full")
        i = self.size
        self.levels[0][i] = leaf
        self._dirty.add(i)
        self.size += 1
        return i

    def update(self, index: int, leaf: int) -> None:
        if index >= self.size:
            raise IndexError(f"leaf {index} not yet appended (size {self.size})")
        self.levels[0][index] = leaf
        self._dirty.add(index)

    def root(self) -> int:
        dirty = self._dirty
        for lvl in range(DEPTH):
            parents = {i >> 1 for i in dirty}
            nodes = self.levels[lvl]
            zero = ZERO[lvl]
            up = self.levels[lvl + 1]
            for p in parents:
                up[p] = hash2(nodes.get(2 * p, zero), nodes.get(2 * p + 1, zero))
            dirty = parents
        self._dirty = set()
        return self._node(DEPTH, 0)
