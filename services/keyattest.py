"""Verifying an Android hardware key attestation.

The app generates a fresh key in the phone's secure hardware (the TEE, or
StrongBox), with our challenge as its attestation challenge. The hardware then
issues a certificate for that key, and the chain above it ends at one of
Google's hardware-attestation roots. The leaf carries a KeyDescription
extension written by the secure hardware itself, which says:

    - the challenge the app supplied,
    - whether the key really is in hardware (security level),
    - the device's boot state: verified boot, locked bootloader,
    - which app asked: package name and the digest of its signing certificate.

So a passing chain proves: a genuine, unmodified Android device, running an APK
signed with our key, asked for this over exactly this challenge. Unlike Play
Integrity it needs no Google account, no Cloud project and no Play services, and
a sideloaded copy of our signed APK passes while a re-signed one does not.

The roots are kept in certs/ and matched by public key, so the chain's top
certificate may be any issuance of a root key (the RSA root was reissued in 2022
with the same key). Google's revocation list is the one thing fetched: it is
public, and leaked device keys are what it exists to catch.

Certificate validity periods are deliberately not checked. Attestation leaves on
real devices carry arbitrary dates (often 1970, or the key's creation time with
no expiry), and Google's own guidance is to rely on the revocation list instead.
"""
import asyncio
import hashlib
import logging
import os
import time

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

import config

logger = logging.getLogger(__name__)

_ROOTS_PATH = os.path.join(os.path.dirname(__file__), "certs", "google_hardware_attestation_roots.pem")
with open(_ROOTS_PATH, "rb") as _fh:
    GOOGLE_ROOTS = x509.load_pem_x509_certificates(_fh.read())

_STATUS_URL = "https://android.googleapis.com/attestation/status"

# SecurityLevel: 0 Software, 1 TrustedEnvironment, 2 StrongBox.
_HARDWARE = {1, 2}
# AuthorizationList tags, from the KeyMint attestation schema.
_TAG_ORIGIN = 702
_TAG_ROOT_OF_TRUST = 704
_TAG_APPLICATION_ID = 709
_ORIGIN_GENERATED = 0
_BOOT_VERIFIED = 0


class AttestationError(Exception):
    """The chain does not prove what it claims. The message says which check failed."""


class Unavailable(Exception):
    """The revocation list could not be read, and there is no recent copy."""


# --- DER --------------------------------------------------------------------
#
# Both the certificates and the KeyDescription are read with a minimal TLV
# walker rather than a full X.509 parser. Real attestation certificates are not
# always strict DER — a StrongBox leaf in Google's own samples writes
# ecdsa-with-SHA256 with an explicit NULL parameter, which `cryptography`
# refuses outright — and a phone should not lose its grant to a parser's
# strictness. The walker reads only the fields the checks need, and refuses
# anything structurally wrong rather than guessing. `cryptography` still does
# every signature check.

def _tlv(data: bytes, pos: int) -> tuple[int, int, bool, bytes, int]:
    """(class, tag number, constructed, value, next position) of the element at pos."""
    if pos >= len(data):
        raise AttestationError("KeyDescription is truncated")
    first = data[pos]
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    pos += 1
    if tag == 0x1F:  # high tag number: base-128, high bit continues
        tag = 0
        while True:
            if pos >= len(data):
                raise AttestationError("KeyDescription tag is truncated")
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if pos >= len(data):
        raise AttestationError("KeyDescription length is truncated")
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise AttestationError("KeyDescription length is malformed")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise AttestationError("KeyDescription element overruns its container")
    return cls, tag, constructed, data[pos:end], end


def _children(value: bytes) -> list[tuple[int, int, bool, bytes]]:
    out, pos = [], 0
    while pos < len(value):
        cls, tag, constructed, inner, pos = _tlv(value, pos)
        out.append((cls, tag, constructed, inner))
    return out


def _raw_children(value: bytes) -> list[tuple[int, int, bytes, bytes]]:
    """(class, tag, contents, the whole encoded element) for each child."""
    out, pos = [], 0
    while pos < len(value):
        start = pos
        cls, tag, _, inner, pos = _tlv(value, pos)
        out.append((cls, tag, inner, value[start:pos]))
    return out


# Signature algorithms by OID contents, to the hash each signs with.
_SIG_ALGS = {
    bytes.fromhex("2a8648ce3d040302"): ("ec", hashes.SHA256()),
    bytes.fromhex("2a8648ce3d040303"): ("ec", hashes.SHA384()),
    bytes.fromhex("2a8648ce3d040304"): ("ec", hashes.SHA512()),
    bytes.fromhex("2a864886f70d01010b"): ("rsa", hashes.SHA256()),
    bytes.fromhex("2a864886f70d01010c"): ("rsa", hashes.SHA384()),
    bytes.fromhex("2a864886f70d01010d"): ("rsa", hashes.SHA512()),
}
_KEY_DESCRIPTION_OID_DER = bytes.fromhex("2b06010401d679020111")  # 1.3.6.1.4.1.11129.2.1.17


class _Cert:
    """The parts of a certificate the checks use, read without judging its DER."""

    def __init__(self, der: bytes):
        _, tag, _, cert, end = _tlv(der, 0)
        if tag != 0x10 or end != len(der):
            raise AttestationError("certificate is not one SEQUENCE")
        parts = _raw_children(cert)
        if len(parts) != 3:
            raise AttestationError("certificate does not have tbs, algorithm and signature")
        (_, _, tbs, self.tbs_raw), (_, _, alg, _), (_, sig_tag, sig, _) = parts
        oid = _children(alg)
        if not oid or oid[0][1] != 0x06 or oid[0][3] not in _SIG_ALGS:
            raise AttestationError("certificate uses an unsupported signature algorithm")
        self.sig_kind, self.sig_hash = _SIG_ALGS[oid[0][3]]
        if sig_tag != 0x03 or not sig or sig[0] != 0:
            raise AttestationError("certificate signature is malformed")
        self.signature = sig[1:]

        fields = _raw_children(tbs)
        if fields and fields[0][0] == 2 and fields[0][1] == 0:  # [0] version
            fields = fields[1:]
        if len(fields) < 6:
            raise AttestationError("certificate is missing fields")
        if fields[0][1] != 0x02:
            raise AttestationError("certificate serial is malformed")
        self.serial = int.from_bytes(fields[0][2], "big", signed=True)
        self.spki = fields[5][3]
        self.key_description = None
        for cls, tag, inner, _ in fields[6:]:
            if cls == 2 and tag == 3:  # [3] extensions
                for _, _, ext, _ in _raw_children(_children(inner)[0][3]):
                    items = _children(ext)
                    if items and items[0][3] == _KEY_DESCRIPTION_OID_DER:
                        self.key_description = items[-1][3]
        try:
            self.public_key = load_der_public_key(self.spki)
        except ValueError as exc:
            raise AttestationError("certificate public key does not parse") from exc

    def signed_by(self, issuer: "_Cert") -> bool:
        """Signature only. Issuer names are not compared: some devices' factory
        certificates do not match their issuer's subject byte for byte, and the
        signature is what carries the proof."""
        key = issuer.public_key
        try:
            if self.sig_kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
                key.verify(self.signature, self.tbs_raw, padding.PKCS1v15(), self.sig_hash)
            elif self.sig_kind == "ec" and isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(self.signature, self.tbs_raw, ec.ECDSA(self.sig_hash))
            else:
                return False
            return True
        except (InvalidSignature, ValueError):
            return False


def _int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def _authorizations(value: bytes) -> dict[int, bytes]:
    """An AuthorizationList: every field is [tag] EXPLICIT, so each child wraps one element."""
    out = {}
    for cls, tag, _, inner in _children(value):
        if cls != 2:  # context-specific
            raise AttestationError("AuthorizationList holds a non-context element")
        wrapped = _children(inner)
        if len(wrapped) != 1:
            raise AttestationError("AuthorizationList field is not a single element")
        out[tag] = wrapped[0][3]
    return out


def _key_description(raw: bytes | None) -> dict:
    if raw is None:
        raise AttestationError("leaf has no key attestation extension")
    _, tag, _, seq, end = _tlv(raw, 0)
    if tag != 0x10 or end != len(raw):
        raise AttestationError("KeyDescription is not one SEQUENCE")
    fields = _children(seq)
    if len(fields) < 8:
        raise AttestationError("KeyDescription has too few fields")
    return {
        "attestation_security_level": _int(fields[1][3]),
        "keymint_security_level": _int(fields[3][3]),
        "challenge": fields[4][3],
        "software": _authorizations(fields[6][3]),
        "hardware": _authorizations(fields[7][3]),
    }


def _root_of_trust(value: bytes) -> tuple[bool, int]:
    """(deviceLocked, verifiedBootState) from a RootOfTrust's contents.

    `value` is already inside the SEQUENCE: _authorizations unwraps one level."""
    fields = _children(value)
    if len(fields) < 3 or fields[1][1] != 0x01 or fields[2][1] != 0x0A:
        raise AttestationError("RootOfTrust is malformed")
    return fields[1][3] != b"\x00", _int(fields[2][3])


def _application_id(value: bytes) -> tuple[set[str], set[bytes]]:
    """(package names, signing-certificate SHA-256 digests) from an AttestationApplicationId."""
    _, tag, _, seq, _ = _tlv(value, 0)
    if tag != 0x10:
        raise AttestationError("AttestationApplicationId is not a SEQUENCE")
    parts = _children(seq)
    if len(parts) != 2 or parts[0][1] != 0x11 or parts[1][1] != 0x11:
        raise AttestationError("AttestationApplicationId is malformed")
    packages = set()
    for _, _, _, info in _children(parts[0][3]):
        name = _children(info)
        if not name or name[0][1] != 0x04:
            raise AttestationError("AttestationPackageInfo is malformed")
        packages.add(name[0][3].decode("utf-8", "replace"))
    digests = {d for _, t, _, d in _children(parts[1][3]) if t == 0x04}
    return packages, digests


# --- the chain ------------------------------------------------------------------

def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


_revoked: set[str] = set()
_revoked_at = 0.0


async def refresh_revocations() -> None:
    """Reads Google's revocation list, keeping the last good copy on failure."""
    global _revoked, _revoked_at
    async with httpx.AsyncClient(timeout=config.CHAIN_HTTP_TIMEOUT) as client:
        resp = await client.get(_STATUS_URL)
    resp.raise_for_status()
    _revoked = {serial.lower() for serial in resp.json()["entries"]}
    _revoked_at = time.time()


async def revoked_serials() -> set[str]:
    """The revoked serials, refreshed hourly and trusted for a day if Google is unreachable."""
    if time.time() - _revoked_at > 3600:
        try:
            await refresh_revocations()
        except Exception as exc:
            logger.warning("could not refresh the attestation revocation list: %s", exc)
    if time.time() - _revoked_at > 86400:
        raise Unavailable("no attestation revocation list from the last day")
    return _revoked


def verify(
    chain_der: list[bytes],
    challenge: bytes,
    *,
    package: str,
    signing_digests: set[bytes],
    revoked: set[str],
    require_locked: bool = True,
    roots: list[x509.Certificate] = GOOGLE_ROOTS,
) -> bytes:
    """Raises AttestationError unless the chain attests a hardware key for our app
    over `challenge`. Returns SHA-256 of the attested key, the grant's identity.

    `roots` exists for tests, which build their own chain because a real one can
    only come off a phone.
    """
    if not 2 <= len(chain_der) <= 10:
        raise AttestationError("chain length is implausible")
    chain = [_Cert(c) for c in chain_der]

    # 1. Every certificate is signed by the next, and the top one is a Google root.
    for cert, issuer in zip(chain, chain[1:]):
        if not cert.signed_by(issuer):
            raise AttestationError("chain is broken: a certificate is not signed by the next")
    if chain[-1].spki not in {_spki(r) for r in roots}:
        raise AttestationError("chain does not end at a Google hardware attestation root")

    # 2. Nothing in it has been revoked. Serials are listed in lowercase hex.
    for cert in chain:
        if format(cert.serial, "x") in revoked:
            raise AttestationError("chain holds a revoked certificate")

    # 3. The leaf's attestation, read from the one certificate the secure hardware wrote.
    desc = _key_description(chain[0].key_description)
    if desc["attestation_security_level"] not in _HARDWARE or desc["keymint_security_level"] not in _HARDWARE:
        raise AttestationError("key is not in secure hardware")
    if desc["challenge"] != challenge:
        raise AttestationError("challenge does not match this challenge and address")

    hardware, software = desc["hardware"], desc["software"]
    origin = hardware.get(_TAG_ORIGIN)
    if origin is None or _int(origin) != _ORIGIN_GENERATED:
        raise AttestationError("key was not generated in the secure hardware")

    rot = hardware.get(_TAG_ROOT_OF_TRUST)
    if rot is None:
        raise AttestationError("attestation has no root of trust")
    locked, boot_state = _root_of_trust(rot)
    if require_locked and (not locked or boot_state != _BOOT_VERIFIED):
        raise AttestationError("device bootloader is unlocked or boot is not verified")

    # The application id is software-enforced on most devices (it is supplied by
    # Android, not the TEE), and hardware-enforced on a few; either is accepted.
    app_id = hardware.get(_TAG_APPLICATION_ID) or software.get(_TAG_APPLICATION_ID)
    if app_id is None:
        raise AttestationError("attestation does not name an app")
    packages, digests = _application_id(app_id)
    if package not in packages:
        raise AttestationError("attestation is for a different app")
    if not digests or not digests <= signing_digests:
        raise AttestationError("app is not signed with our certificate")

    return hashlib.sha256(chain[0].spki).digest()


async def verify_async(chain_der: list[bytes], challenge: bytes) -> bytes:
    """verify() with the configured app, and the revocation list fetched first."""
    revoked = await revoked_serials()
    return await asyncio.to_thread(
        verify,
        chain_der,
        challenge,
        package=config.ANDROID_PACKAGE,
        signing_digests=config.ANDROID_SIGNING_CERT_SHA256,
        revoked=revoked,
        require_locked=config.ANDROID_REQUIRE_LOCKED_BOOTLOADER,
    )
