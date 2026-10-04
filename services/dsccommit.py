"""The DSC commitment of a Document Signer certificate, as the chain computes it.

x/pki/certs.DscCommitmentOf: Poseidon2 over [curve tag, key byte, key byte,
...], one field element per byte of the canonical public key (ECDSA: x || y,
each padded to the curve's coordinate width), or for RSA over [10, e, modulus
byte, ...] (the modulus big-endian, minimal): the circuits take the exponent
as a witness, so it is committed. The register circuit outputs the same value as public input
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

# x/pki/certs/commitment.go CurveTag: consensus values. 7 (RSA without its
# exponent) is retired.
TAG_P256, TAG_P384, TAG_P521 = 1, 2, 3
TAG_BP256, TAG_BP384, TAG_BP512 = 4, 5, 6
TAG_P224, TAG_BP224 = 8, 9
TAG_RSA_E = 10

_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"
_OID_PRIME_FIELD = "1.2.840.10045.1.1"


def _h(s: str) -> int:
    return int(s, 16)


# (tag, p, a, b, gx, gy, n) by named-curve OID; x/pki/certs/curves.go.
_CURVES = {
    "1.3.132.0.33": (TAG_P224,
                     _h("ffffffffffffffffffffffffffffffff000000000000000000000001"),
                     _h("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
                     _h("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
                     _h("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
                     _h("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
                     _h("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d")),
    "1.2.840.10045.3.1.7": (TAG_P256,
                            _h("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                            _h("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
                            _h("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                            _h("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                            _h("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                            _h("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")),
    "1.3.132.0.34": (TAG_P384,
                     _h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                     _h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
                     _h("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
                     _h("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
                     _h("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
                     _h("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")),
    "1.3.132.0.35": (TAG_P521, 2**521 - 1, 2**521 - 4,
                     _h("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
                     _h("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
                     _h("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),
                     _h("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409")),
    "1.3.36.3.3.2.8.1.1.5": (TAG_BP224,
                             _h("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff"),
                             _h("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43"),
                             _h("2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b"),
                             _h("0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d"),
                             _h("58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd"),
                             _h("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f")),
    "1.3.36.3.3.2.8.1.1.7": (TAG_BP256,
                             _h("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
                             _h("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9"),
                             _h("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6"),
                             _h("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"),
                             _h("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"),
                             _h("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7")),
    "1.3.36.3.3.2.8.1.1.11": (TAG_BP384,
                              _h("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53"),
                              _h("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826"),
                              _h("04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11"),
                              _h("1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e"),
                              _h("8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315"),
                              _h("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565")),
    "1.3.36.3.3.2.8.1.1.13": (TAG_BP512,
                              _h("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3"),
                              _h("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca"),
                              _h("3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723"),
                              _h("81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822"),
                              _h("7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"),
                              _h("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069")),
}


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
        tag, p = _CURVES[oid][:2]
        return tag, (p.bit_length() + 7) // 8
    ec = params.seq()
    ec.read(0x02)  # version
    field = ec.seq()
    if _oid(field.read(0x06)[1]) != _OID_PRIME_FIELD:
        raise _Bad("not a prime field")
    p = _uint(field.read(0x02)[1])
    curve = ec.seq()  # curve { a, b, seed? }
    a = int.from_bytes(curve.read(0x04)[1], "big")
    b = int.from_bytes(curve.read(0x04)[1], "big")
    byte_len = (p.bit_length() + 7) // 8
    base = ec.read(0x04)[1]
    if len(base) != 1 + 2 * byte_len or base[0] != 0x04:
        raise _Bad("bad base point")
    gx = int.from_bytes(base[1:1 + byte_len], "big")
    gy = int.from_bytes(base[1 + byte_len:], "big")
    n = _uint(ec.read(0x02)[1])
    cofactor = _uint(ec.read(0x02)[1]) if not ec.done() else 1
    for params in _CURVES.values():
        if params[1:] == (p, a, b, gx, gy, n) and cofactor == 1:
            return params[0], byte_len
    raise _Bad("explicit curve has no commitment tag")


def canonical_key(dsc_der: bytes) -> tuple[tuple[int, ...], bytes]:
    """(the field elements ahead of the key: (tag,) for ECDSA, (10, e) for RSA;
    the canonical public-key bytes) of a certificate. Raises ValueError."""
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
            exponent = _uint(rsa.read(0x02)[1])
            out = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
            if len(out) > MAX_PUBLIC_KEY_BYTES:
                raise _Bad("key too large")
            if not 0 < exponent < 1 << 63:
                raise _Bad("RSA exponent out of range")
            return (TAG_RSA_E, exponent), out
        if alg_oid == _OID_EC:
            tag, byte_len = _curve(algo)
            if 2 * byte_len > MAX_PUBLIC_KEY_BYTES:
                raise _Bad("key too large")
            if len(key) != 1 + 2 * byte_len or key[0] != 0x04:
                raise _Bad("EC point not uncompressed / wrong length")
            return (tag,), key[1:]
        raise _Bad(f"unsupported public-key algorithm {alg_oid}")
    except (_Bad, IndexError) as exc:
        raise ValueError(f"DSC certificate: {exc}") from None


def commitment_of_key(head: tuple[int, ...], key: bytes) -> bytes:
    """x/pki/certs.DscCommitmentOf: Poseidon2(head ‖ key bytes), 32 bytes big-endian."""
    return privacy.field_bytes(poseidon2.hash_fields(list(head) + list(key)))


# (tag, canonical key) -> commitment. A passport's DSC is shared by every
# passport it signed; keyed by the key itself, so a certificate re-issued
# with a new serial or signature over the same key costs nothing again,
# while a request that varies only the certificate around one key cannot
# miss the cache.
_cache: "OrderedDict[tuple[tuple[int, ...], bytes], bytes]" = OrderedDict()
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


def _cached(tag: tuple[int, ...], key: bytes) -> bytes:
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
