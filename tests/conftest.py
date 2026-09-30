"""Shared fixtures: a throwaway replay database, a chain whose sends are recorded
instead of broadcast, and a stand-in for Apple's App Attest CA.

A real attestation can only come off a device, so the tests build the same
structure Apple does — root, intermediate, leaf with the nonce extension, CBOR
around it — under a root they generated, and hand the verifier that root."""
import base64
import datetime
import hashlib
import os
import sys

import cbor2
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from routers import gas  # noqa: E402
from services import appattest, chain, challenges, replay  # noqa: E402

ADDRESS = "earth1qqqsyqcyq5rqwzqfpg9scrgwpugpzysncc2uls"
APP_ID = "XD8VH8WKVX.network.erth.EarthWallet"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public_key, signing_key, *, ca: bool, extensions=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signing_key, hashes.SHA384() if ca else hashes.SHA256())


class FakeAppleCA:
    """Root and intermediate, issuing leaves the way Apple's App Attest CA does."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert("Test App Attestation Root", "Test App Attestation Root",
                          self.root_key.public_key(), self.root_key, ca=True)
        self.inter_key = ec.generate_private_key(ec.SECP384R1())
        self.inter = _cert("Test App Attestation CA 1", "Test App Attestation Root",
                           self.inter_key.public_key(), self.root_key, ca=True)

    def attest(self, client_data_hash: bytes, *, app_id=APP_ID, aaguid=appattest.AAGUID_PRODUCTION,
               counter=0, nonce_override: bytes | None = None, key_id_override: bytes | None = None):
        """Returns (key_id, attestation bytes) for a fresh device key."""
        device_key = ec.generate_private_key(ec.SECP256R1())
        point = device_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        key_id = hashlib.sha256(point).digest()
        cred_id = key_id_override or key_id
        auth_data = (
            hashlib.sha256(app_id.encode()).digest()
            + b"\x40"
            + counter.to_bytes(4, "big")
            + aaguid
            + len(cred_id).to_bytes(2, "big")
            + cred_id
        )
        nonce = nonce_override or hashlib.sha256(auth_data + client_data_hash).digest()
        ext = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.2.840.113635.100.8.2"), bytes.fromhex("3024a1220420") + nonce
        )
        leaf = _cert("device", "Test App Attestation CA 1", device_key.public_key(), self.inter_key,
                     ca=False, extensions=[ext])
        att = cbor2.dumps({
            "fmt": "apple-appattest",
            "attStmt": {"x5c": [leaf.public_bytes(Encoding.DER), self.inter.public_bytes(Encoding.DER)],
                        "receipt": b""},
            "authData": auth_data,
        })
        return base64.b64encode(key_id).decode(), att


@pytest.fixture
def apple(monkeypatch):
    ca = FakeAppleCA()
    real = appattest.verify

    def verify_with_test_root(*args, **kwargs):
        kwargs["root"] = ca.root
        return real(*args, **kwargs)

    monkeypatch.setattr(appattest, "verify", verify_with_test_root)
    return ca


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(config, "IOS_APP_ID", APP_ID)
    monkeypatch.setattr(replay, "_conn", None)
    challenges.reset()
    yield
    if replay._conn is not None:
        replay._conn.close()


@pytest.fixture
def sends(monkeypatch):
    """Records every address dust is sent to, in place of the chain."""
    sent: list[str] = []

    async def fake_send(address: str) -> str:
        sent.append(address)
        return f"HASH{len(sent)}"

    monkeypatch.setattr(chain, "send_dust", fake_send)
    return sent


@pytest.fixture
def client():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(gas.router)
    return TestClient(app)


def get_challenge(client, address=ADDRESS) -> str:
    resp = client.post("/gas/challenge", json={"address": address})
    assert resp.status_code == 200, resp.text
    return resp.json()["challenge"]


# --- Android key attestation ------------------------------------------------------

SIGNING_DIGEST = hashlib.sha256(b"our release certificate").digest()


def _der(tag: bytes, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return tag + length + content


def _ctx(number: int, inner: bytes) -> bytes:
    """[number] EXPLICIT, high-tag form (every AuthorizationList tag used here is >= 31)."""
    digits = []
    while True:
        digits.insert(0, number & 0x7F)
        number >>= 7
        if not number:
            break
    tag = bytes([0xBF] + [d | 0x80 for d in digits[:-1]] + [digits[-1]])
    return _der(tag, inner)


def _int(v: int) -> bytes:
    return _der(b"\x02", v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _enum(v: int) -> bytes:
    return _der(b"\x0a", bytes([v]))


def key_description(challenge: bytes, *, package="network.erth.wallet", digests=(SIGNING_DIGEST,),
                    security=1, locked=True, boot=0, origin=0, app_id_in_hardware=False) -> bytes:
    app_id = _der(b"\x30",
                  _der(b"\x31", _der(b"\x30", _der(b"\x04", package.encode()) + _int(1)))
                  + _der(b"\x31", b"".join(_der(b"\x04", d) for d in digests)))
    app_field = _ctx(709, _der(b"\x04", app_id))
    root_of_trust = _der(b"\x30", _der(b"\x04", bytes(32)) + _der(b"\x01", b"\xff" if locked else b"\x00")
                         + _enum(boot) + _der(b"\x04", bytes(32)))
    hardware = _ctx(702, _int(origin)) + _ctx(704, root_of_trust) + (app_field if app_id_in_hardware else b"")
    software = b"" if app_id_in_hardware else app_field
    return _der(b"\x30", _int(200) + _enum(security) + _int(200) + _enum(security)
                + _der(b"\x04", challenge) + _der(b"\x04", b"")
                + _der(b"\x30", software) + _der(b"\x30", hardware))


class FakeGoogleCA:
    """A hardware-attestation root and intermediate, issuing leaves with a KeyDescription."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert("Test Key Attestation Root", "Test Key Attestation Root",
                          self.root_key.public_key(), self.root_key, ca=True)
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.inter = _cert("Test Key Attestation Intermediate", "Test Key Attestation Root",
                           self.inter_key.public_key(), self.root_key, ca=True)

    def attest(self, challenge: bytes, **kwargs) -> list[str]:
        device_key = ec.generate_private_key(ec.SECP256R1())
        ext = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                                         key_description(challenge, **kwargs))
        leaf = _cert("Android Keystore Key", "Test Key Attestation Intermediate",
                     device_key.public_key(), self.inter_key, ca=False, extensions=[ext])
        return [base64.b64encode(c.public_bytes(Encoding.DER)).decode() for c in (leaf, self.inter, self.root)]


@pytest.fixture
def google(monkeypatch):
    """Android configured, verifying against a test root, with an empty revocation list."""
    from services import keyattest

    ca = FakeGoogleCA()
    monkeypatch.setattr(config, "ANDROID_SIGNING_CERT_SHA256", frozenset({SIGNING_DIGEST}))
    monkeypatch.setattr(config, "ANDROID_REQUIRE_LOCKED_BOOTLOADER", True)
    monkeypatch.setattr(keyattest, "GOOGLE_ROOTS", [ca.root])
    real = keyattest.verify
    monkeypatch.setattr(keyattest, "verify", lambda *a, **k: real(*a, **{**k, "roots": [ca.root]}))
    ca.revoked = set()

    async def revoked():
        return ca.revoked

    monkeypatch.setattr(keyattest, "revoked_serials", revoked)
    return ca
