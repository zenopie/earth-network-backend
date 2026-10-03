"""The DSC commitment of a Document Signer certificate, as the chain computes it.

x/pki/certs.DscCommitmentOf: Poseidon2 over [curve tag, key byte, key byte,
...], one field element per byte of the canonical public key (ECDSA: x || y,
each padded to the curve's coordinate width; RSA: the modulus big-endian,
minimal). The register circuit outputs the same value as public input
dsc_key_index, and the chain requires the two to match ("proof is not bound
to the supplied DSC").

/gas/register uses it to admit a request to the reserved lane only when the
dsc_der it sends really is the signer whose commitment it names (audit-4
B1): a commitment is public, so without this junk could copy a known one
into public_signals[3] beside any certificate at all. The lane hashes with
lane_commitment (audit-5 M1): a key of at most LANE_MAX_KEY_BYTES, in a
worker thread, one at a time, cached by key.

The certificate is parsed the way x/pki/certs.ParseCert does it (leniently:
Brainpool and explicit-parameter curves, which the `cryptography` package
refuses, are ~31% of the real ICAO store). Anything this cannot parse, or a
curve the chain has no tag for, is None: no reserved lane, which is the safe
answer — the ordinary lane is still open, and gas-check is the authority.
"""
import asyncio
from collections import OrderedDict

from services.zk import poseidon2, privacy

# x/pki/certs/parse.go MaxPublicKeyBytes: the chain refuses a larger key, and
# the hash costs a permutation per three bytes.
MAX_PUBLIC_KEY_BYTES = 2048

# x/pki/certs/commitment.go CurveTag: consensus values.
TAG_P256, TAG_P384, TAG_P521 = 1, 2, 3
TAG_BP256, TAG_BP384, TAG_BP512 = 4, 5, 6
TAG_RSA = 7

_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"
_OID_PRIME_FIELD = "1.2.840.10045.1.1"


def _h(s: str) -> int:
    return int(s, 16)


# (tag, field prime p, group order n) by named-curve OID; x/pki/certs/curves.go.
_CURVES = {
    "1.2.840.10045.3.1.7": (TAG_P256,
                            _h("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                            _h("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")),
    "1.3.132.0.34": (TAG_P384,
                     _h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                     _h("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")),
    "1.3.132.0.35": (TAG_P521, 2**521 - 1,
                     _h("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409")),
    "1.3.36.3.3.2.8.1.1.7": (TAG_BP256,
                             _h("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
                             _h("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7")),
    "1.3.36.3.3.2.8.1.1.11": (TAG_BP384,
                              _h("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53"),
                              _h("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565")),
    "1.3.36.3.3.2.8.1.1.13": (TAG_BP512,
                              _h("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3"),
                              _h("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069")),
}
_BY_PRIME = {p: (tag, p, n) for tag, p, n in _CURVES.values()}


class _Bad(Exception):
    pass


class _Der:
    """A cursor over DER bytes: just enough of cryptobyte for an X.509 SPKI."""

    def __init__(self, data: bytes):
        self.b, self.i = data, 0

    def done(self) -> bool:
        return self.i >= len(self.b)

    def peek(self) -> int:
        if self.done():
            raise _Bad("truncated")
        return self.b[self.i]

    def read(self, tag: int | None = None) -> tuple[int, bytes]:
        b, i = self.b, self.i
        if i + 2 > len(b):
            raise _Bad("truncated")
        t, ln = b[i], b[i + 1]
        if t & 0x1F == 0x1F:
            raise _Bad("high tag number")
        i += 2
        if ln & 0x80:
            k = ln & 0x7F
            if k == 0 or k > 4 or i + k > len(b):
                raise _Bad("bad length")
            ln = int.from_bytes(b[i:i + k], "big")
            i += k
        if i + ln > len(b):
            raise _Bad("truncated")
        if tag is not None and t != tag:
            raise _Bad(f"want tag {tag:#x}, got {t:#x}")
        self.i = i + ln
        return t, b[i:i + ln]

    def seq(self) -> "_Der":
        return _Der(self.read(0x30)[1])


def _oid(raw: bytes) -> str:
    if not raw:
        raise _Bad("empty OID")
    parts, v = [], 0
    for c in raw:
        v = v << 7 | (c & 0x7F)
        if not c & 0x80:
            parts.append(v)
            v = 0
    first = min(parts[0] // 40, 2)
    return ".".join(str(x) for x in [first, parts[0] - 40 * first] + parts[1:])


def _uint(raw: bytes) -> int:
    if not raw or raw[0] & 0x80:
        raise _Bad("not a positive INTEGER")
    return int.from_bytes(raw, "big")


def _curve(params: _Der) -> tuple[int, int]:
    """(tag, coordinate byte length) of an EC SPKI's parameters, named or explicit."""
    if params.peek() == 0x06:
        oid = _oid(params.read(0x06)[1])
        if oid not in _CURVES:
            raise _Bad("curve has no commitment tag")
        tag, p, _ = _CURVES[oid]
        return tag, (p.bit_length() + 7) // 8
    ec = params.seq()
    ec.read(0x02)  # version
    field = ec.seq()
    if _oid(field.read(0x06)[1]) != _OID_PRIME_FIELD:
        raise _Bad("not a prime field")
    p = _uint(field.read(0x02)[1])
    ec.seq()  # curve { a, b, seed? }
    byte_len = (p.bit_length() + 7) // 8
    base = ec.read(0x04)[1]
    if len(base) != 1 + 2 * byte_len or base[0] != 0x04:
        raise _Bad("bad base point")
    n = _uint(ec.read(0x02)[1])
    known = _BY_PRIME.get(p)
    if known is None or known[2] != n:
        raise _Bad("explicit curve has no commitment tag")
    return known[0], byte_len


def canonical_key(dsc_der: bytes) -> tuple[int, bytes]:
    """(curve tag, canonical public-key bytes) of a certificate. Raises ValueError."""
    try:
        cert = _Der(dsc_der).seq()
        tbs = cert.seq()
        if tbs.peek() == 0xA0:
            tbs.read(0xA0)  # version [0]
        tbs.read(0x02)  # serial
        tbs.read(0x30)  # inner signature algorithm
        tbs.read(0x30)  # issuer
        tbs.read(0x30)  # validity
        tbs.read(0x30)  # subject
        spki = tbs.seq()
        algo = spki.seq()
        alg_oid = _oid(algo.read(0x06)[1])
        bits = spki.read(0x03)[1]
        if not bits or bits[0] != 0:
            raise _Bad("key BIT STRING has unused bits")
        key = bits[1:]
        if alg_oid == _OID_RSA:
            rsa = _Der(key).seq()
            modulus = _uint(rsa.read(0x02)[1])
            out = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
            if len(out) > MAX_PUBLIC_KEY_BYTES:
                raise _Bad("key too large")
            return TAG_RSA, out
        if alg_oid == _OID_EC:
            tag, byte_len = _curve(algo)
            if 2 * byte_len > MAX_PUBLIC_KEY_BYTES:
                raise _Bad("key too large")
            if len(key) != 1 + 2 * byte_len or key[0] != 0x04:
                raise _Bad("EC point not uncompressed / wrong length")
            return tag, key[1:]
        raise _Bad(f"unsupported public-key algorithm {alg_oid}")
    except (_Bad, IndexError) as exc:
        raise ValueError(f"DSC certificate: {exc}") from None


def commitment_of_key(tag: int, key: bytes) -> bytes:
    """x/pki/certs.DscCommitment(tag, key), 32 bytes big-endian."""
    return privacy.field_bytes(poseidon2.hash_fields([tag] + list(key)))


# (tag, canonical key) -> commitment. A passport's DSC is shared by every
# passport it signed; keyed by the key itself, so a certificate re-issued
# with a new serial or signature over the same key costs nothing again,
# while a request that varies only the certificate around one key cannot
# miss the cache.
_cache: "OrderedDict[tuple[int, bytes], bytes]" = OrderedDict()
_CACHE_MAX = 512

# The reserved lane's own bound on the key it hashes (audit-5 M1): RSA 4096,
# the largest real Document Signer key. The chain takes up to
# MAX_PUBLIC_KEY_BYTES (consensus), and a key between the two still reaches
# the ordinary lane; only the lane, which hashes on this process, is
# stricter. Poseidon2 here is pure Python, one field element a byte.
LANE_MAX_KEY_BYTES = 512

# One commitment computed at a time, off the event loop: a burst of distinct
# keys queues here instead of stalling every other request.
_lock: asyncio.Lock | None = None


def _cached(tag: int, key: bytes) -> bytes:
    k = (tag, key)
    if k in _cache:
        _cache.move_to_end(k)
        return _cache[k]
    value = commitment_of_key(tag, key)
    _cache[k] = value
    while len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)
    return value


def commitment(dsc_der: bytes) -> bytes | None:
    """The chain's DSC commitment of a certificate, or None if it has none."""
    try:
        tag, key = canonical_key(dsc_der)
    except ValueError:
        return None
    return _cached(tag, key)


async def lane_commitment(dsc_der: bytes) -> bytes | None:
    """commitment(dsc_der) for the reserved lane: None for a key past
    LANE_MAX_KEY_BYTES (never hashed), and computed in a worker thread, one
    at a time, so the hash never runs on the event loop."""
    global _lock
    try:
        tag, key = canonical_key(dsc_der)  # a DER walk: cheap
    except ValueError:
        return None
    if len(key) > LANE_MAX_KEY_BYTES:
        return None
    hit = _cache.get((tag, key))
    if hit is not None:
        _cache.move_to_end((tag, key))
        return hit
    if _lock is None:
        _lock = asyncio.Lock()
    async with _lock:
        return await asyncio.to_thread(_cached, tag, key)


def reset() -> None:
    global _lock
    _cache.clear()
    _lock = None
