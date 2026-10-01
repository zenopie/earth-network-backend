"""Poseidon2 over BN254, bit for bit the chain's zk/poseidon2 (and Noir's).

t=4, d=5, 8 full + 56 partial rounds, the Barretenberg sponge: rate 3,
capacity 1, IV = len(inputs) << 64, one output element. Pure Python on ints;
about 0.1 ms a permutation, which is plenty for rebuilding trees offline.
"""
from .constants import MAT_DIAG4, ROUND_CONSTANTS

# The BN254 scalar field modulus (fr).
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

_ROUNDS_F_BEGIN = 4
_ROUNDS_P = 56
_TOTAL = 64
_RATE = 3


def _sbox(x: int) -> int:
    x2 = x * x % P
    return x2 * x2 % P * x % P


def _external(s: list[int]) -> list[int]:
    t0 = s[0] + s[1]
    t1 = s[2] + s[3]
    t2 = 2 * s[1] + t1
    t3 = 2 * s[3] + t0
    t4 = 4 * t1 + t3
    t5 = 4 * t0 + t2
    t6 = t3 + t5
    t7 = t2 + t4
    return [t6 % P, t5 % P, t7 % P, t4 % P]


def _internal(s: list[int]) -> list[int]:
    total = s[0] + s[1] + s[2] + s[3]
    return [(MAT_DIAG4[i] * s[i] + total) % P for i in range(4)]


def permute(state: list[int]) -> list[int]:
    s = _external(state)
    for r in range(_ROUNDS_F_BEGIN):
        rc = ROUND_CONSTANTS[r]
        s = _external([_sbox((s[i] + rc[i]) % P) for i in range(4)])
    for r in range(_ROUNDS_F_BEGIN, _ROUNDS_F_BEGIN + _ROUNDS_P):
        s[0] = _sbox((s[0] + ROUND_CONSTANTS[r][0]) % P)
        s = _internal(s)
    for r in range(_ROUNDS_F_BEGIN + _ROUNDS_P, _TOTAL):
        rc = ROUND_CONSTANTS[r]
        s = _external([_sbox((s[i] + rc[i]) % P) for i in range(4)])
    return s


def hash_fields(inputs: list[int]) -> int:
    """Poseidon2::hash of field elements (each already reduced below P)."""
    state = [0, 0, 0, (len(inputs) << 64) % P]
    cache: list[int] = []

    def duplex() -> None:
        nonlocal state
        padded = cache + [0] * (_RATE - len(cache))
        state = permute([(state[i] + padded[i]) % P if i < _RATE else state[i] for i in range(4)])

    for x in inputs:
        if len(cache) == _RATE:
            duplex()
            cache = [x]
        else:
            cache.append(x)
    duplex()
    return state[0]


def hash2(left: int, right: int) -> int:
    """A Merkle node: Poseidon2([left, right]). One permutation."""
    s = permute([left, right, 0, 2 << 64])
    return s[0]
