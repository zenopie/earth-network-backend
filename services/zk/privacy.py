"""The chain's domain-tagged derivations (zk/privacy), as far as the backend needs
them: checking field encodings, asset ids and note commitments, and identity
leaves. Every function must match its Go twin exactly; tests/test_zk.py pins
them to vectors produced by the Go code.
"""
from .poseidon2 import P, hash_fields


def tag(s: str) -> int:
    return int.from_bytes(s.encode(), "big") % P


TAG_ID = tag("earth.id")
TAG_OWNER = tag("earth.owner")
TAG_LEAF = tag("earth.leaf")
TAG_PC = tag("earth.pc")
TAG_CM = tag("earth.cm")
TAG_ASSET = tag("earth.asset")
TAG_STAKE = tag("earth.stake")
TAG_SPC = tag("earth.spc")
TAG_REG = tag("earth.reg")
TAG_BYTES = tag("earth.bytes")


def H(*xs: int) -> int:
    return hash_fields(list(xs))


def field_from_bytes(b: bytes) -> int:
    """privacy.FieldFromBytes: exactly 32 bytes, big-endian, canonical (< P)."""
    if len(b) != 32:
        raise ValueError(f"field element must be 32 bytes, got {len(b)}")
    v = int.from_bytes(b, "big")
    if v >= P:
        raise ValueError("field element is not canonical (>= modulus)")
    return v


def field_bytes(v: int) -> bytes:
    return v.to_bytes(32, "big")


def _chunks31(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i + 31], "big") for i in range(0, len(b), 31)]


def asset_id(denom: str) -> int:
    b = denom.encode()
    return H(TAG_ASSET, len(b), *_chunks31(b))


def idc(id_secret: int) -> int:
    return H(TAG_ID, id_secret)


def owner_pk(nk: int) -> int:
    return H(TAG_OWNER, nk)


def pc(owner: int, rho: int, rcm: int) -> int:
    return H(TAG_PC, owner, rho, rcm)


def cm(asset: int, value: int, pc_: int) -> int:
    return H(TAG_CM, asset, value, pc_)


def country_field(cc: str) -> int:
    if len(cc) != 2 or not ("A" <= cc[0] <= "Z") or not ("A" <= cc[1] <= "Z"):
        return 0
    return (ord(cc[0]) << 8) | ord(cc[1])


def identity_leaf(idc_: int, dsc_key: int, country: int, activated_at: int) -> int:
    return H(TAG_LEAF, idc_, dsc_key, country, activated_at)


def stake_pc(owner: int, rho: int, rcm: int) -> int:
    """privacy.StakePC: a stake note's hidden owner."""
    return H(TAG_SPC, owner, rho, rcm)


def stake_cm(asset: int, amount: int, spc: int) -> int:
    """privacy.StakeCM: a stake tree leaf, asset = asset_id(derth/<valoper> or unbond/<valoper>/<epoch>)."""
    return H(TAG_STAKE, asset, amount, spc)


def bytes_field(b: bytes) -> int:
    """privacy.Bytes: H(TAG_BYTES, len, 31-byte chunks...)."""
    return H(TAG_BYTES, len(b), *_chunks31(b))


def registration_binding(idc_: int, pc_anml: int, pc_erth: int, affiliate: int) -> int:
    """privacy.RegistrationBinding: the passport proof's address input.
    affiliate is 0 for none, else bytes_field(its address bytes)."""
    return H(TAG_REG, idc_, pc_anml, pc_erth, affiliate)
