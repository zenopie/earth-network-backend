"""Verifying an Apple App Attest attestation.

Follows Apple's "Validating apps that connect to your server", step for step,
and refuses on the first thing that does not hold. What a passing attestation
proves: the key `key_id` names was generated in the Secure Enclave of a real
Apple device, by a build of the app `IOS_APP_ID` names, signed by our team, and
the app asked for it over exactly `client_data_hash`. Nothing else about the
request is trusted.

No Apple credentials are involved. The chain is checked against Apple's App
Attestation root, kept in certs/ rather than fetched, so a network position
between us and apple.com cannot swap it.
"""
import base64
import datetime
import hashlib
import os

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ROOT_PATH = os.path.join(os.path.dirname(__file__), "certs", "apple_app_attestation_root_ca.pem")
with open(_ROOT_PATH, "rb") as _fh:
    APPLE_ROOT = x509.load_pem_x509_certificate(_fh.read())

# The leaf carries the nonce in this extension, DER-encoded as
# SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }. Compared as whole bytes
# against the expected encoding rather than parsed loosely: there is exactly one
# valid shape, and accepting others is how a parser gets talked into reading a
# nonce from somewhere it should not.
_NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
_NONCE_PREFIX = bytes.fromhex("3024a1220420")

# The environment the key was made in. Production is what TestFlight and the
# App Store use; development is a build run from Xcode.
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"


class AttestationError(Exception):
    """The attestation does not prove what it claims. The message says which step failed."""


def _check_validity(cert: x509.Certificate, now: datetime.datetime, name: str) -> None:
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise AttestationError(f"{name} certificate is outside its validity period")


def verify(
    attestation: bytes,
    key_id: str,
    client_data_hash: bytes,
    *,
    app_id: str,
    allow_development: bool,
    root: x509.Certificate = APPLE_ROOT,
    now: datetime.datetime | None = None,
) -> None:
    """Raises AttestationError unless `attestation` is valid for `key_id` over `client_data_hash`.

    `app_id` is TEAMID.bundle.id. `root` and `now` exist for tests, which build
    their own chain because a real attestation can only come off a device.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        key_id_bytes = base64.b64decode(key_id, validate=True)
    except ValueError as exc:
        raise AttestationError("key_id is not base64") from exc

    try:
        obj = cbor2.loads(attestation)
    except Exception as exc:  # cbor2 raises several unrelated types on garbage
        raise AttestationError("attestation is not CBOR") from exc
    if not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
        raise AttestationError("attestation format is not apple-appattest")
    stmt, auth_data = obj.get("attStmt"), obj.get("authData")
    if not isinstance(stmt, dict) or not isinstance(auth_data, bytes):
        raise AttestationError("attestation is missing attStmt or authData")
    x5c = stmt.get("x5c")
    if not isinstance(x5c, list) or len(x5c) != 2 or not all(isinstance(c, bytes) for c in x5c):
        raise AttestationError("x5c must hold exactly the leaf and the intermediate")

    # 1. The leaf chains to Apple's root through the intermediate.
    try:
        leaf, intermediate = (x509.load_der_x509_certificate(c) for c in x5c)
    except ValueError as exc:
        raise AttestationError("x5c holds a certificate that does not parse") from exc
    _check_validity(root, now, "root")
    _check_validity(intermediate, now, "intermediate")
    _check_validity(leaf, now, "leaf")
    try:
        intermediate.verify_directly_issued_by(root)
        leaf.verify_directly_issued_by(intermediate)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise AttestationError("certificate chain does not lead to Apple's App Attestation root") from exc

    # 2-4. The leaf commits to SHA-256(authData || clientDataHash).
    nonce = hashlib.sha256(auth_data + client_data_hash).digest()
    try:
        ext = leaf.extensions.get_extension_for_oid(_NONCE_OID).value
    except x509.ExtensionNotFound as exc:
        raise AttestationError("leaf has no App Attest nonce extension") from exc
    if getattr(ext, "value", None) != _NONCE_PREFIX + nonce:
        raise AttestationError("nonce does not match this challenge and address")

    # 5. The leaf's public key is the key the app named.
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise AttestationError("leaf key is not an EC key")
    point = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if hashlib.sha256(point).digest() != key_id_bytes:
        raise AttestationError("key_id is not the attested key")

    # authData: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId(...)
    if len(auth_data) < 55:
        raise AttestationError("authData is truncated")
    rp_id_hash = auth_data[0:32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    aaguid = auth_data[37:53]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55 : 55 + cred_len]

    # 6. Made by our app — team id and bundle id both, so nobody else's app
    # can mint attestations we accept.
    if rp_id_hash != hashlib.sha256(app_id.encode("utf-8")).digest():
        raise AttestationError("attestation is for a different app")
    # 7. A fresh key has never signed anything.
    if sign_count != 0:
        raise AttestationError("counter is not zero")
    # 8. The environment.
    allowed = {AAGUID_PRODUCTION} | ({AAGUID_DEVELOPMENT} if allow_development else set())
    if aaguid not in allowed:
        raise AttestationError("attestation is from an environment this server does not accept")
    # 9. The credential is the key.
    if cred_id != key_id_bytes:
        raise AttestationError("credential id is not key_id")
