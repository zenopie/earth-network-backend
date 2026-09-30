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
