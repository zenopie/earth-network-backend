"""The grant endpoints: what an attestation must prove before dust moves."""
import base64
import hashlib
import time

import pytest

import config
from services import appattest, challenges, chain, keyattest
from tests.conftest import ADDRESS, SIGNING_DIGEST, FakeGoogleCA, get_challenge

OTHER = "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"


def ios_body(apple, client, address=ADDRESS, **attest_kwargs):
    challenge = get_challenge(client, address)
    key_id, att = apple.attest(challenges.bound_digest(challenge, address), **attest_kwargs)
    return {"address": address, "challenge": challenge, "key_id": key_id,
            "attestation": base64.b64encode(att).decode()}


# --- challenge ---------------------------------------------------------------

def test_challenge_refuses_a_non_earth_address(client):
    assert client.post("/gas/challenge", json={"address": "cosmos1abc"}).status_code == 400


def test_bound_digest_vector():
    # The vector the apps' unit tests carry: 32 zero bytes, then "earth1test".
    assert challenges.bound_digest("A" * 43, "earth1test").hex() == (
        hashlib.sha256(bytes(32) + b"earth1test").hexdigest()
    )


# --- iOS -----------------------------------------------------------------------

def test_ios_grant(apple, client, sends):
    resp = client.post("/gas/ios", json=ios_body(apple, client))
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "success"
    assert sends == [ADDRESS]


def test_ios_challenge_is_single_use(apple, client, sends):
    body = ios_body(apple, client)
    assert client.post("/gas/ios", json=body).status_code == 200
    assert client.post("/gas/ios", json=body).status_code == 409
    assert sends == [ADDRESS]


def test_ios_attestation_cannot_be_moved_to_another_address(apple, client, sends):
    body = ios_body(apple, client)
    # A fresh challenge for someone else, carrying the first attestation.
    body["challenge"] = get_challenge(client, OTHER)
    body["address"] = OTHER
    assert client.post("/gas/ios", json=body).status_code == 403
    assert sends == []


def test_ios_challenge_issued_to_someone_else_is_refused(apple, client, sends):
    body = ios_body(apple, client)
    body["address"] = OTHER
    assert client.post("/gas/ios", json=body).status_code == 409
    assert sends == []


@pytest.mark.parametrize("kwargs", [
    {"app_id": "OTHERTEAM.network.erth.EarthWallet"},
    {"counter": 1},
    {"aaguid": b"notappattest0000"},
    {"nonce_override": bytes(32)},
    {"key_id_override": bytes(32)},
])
def test_ios_refuses_a_bad_attestation(apple, client, sends, kwargs):
    assert client.post("/gas/ios", json=ios_body(apple, client, **kwargs)).status_code == 403
    assert sends == []


def test_ios_development_environment_is_configurable(apple, client, sends, monkeypatch):
    dev = {"aaguid": appattest.AAGUID_DEVELOPMENT}
    monkeypatch.setattr(config, "APP_ATTEST_ALLOW_DEVELOPMENT", False)
    assert client.post("/gas/ios", json=ios_body(apple, client, **dev)).status_code == 403
    monkeypatch.setattr(config, "APP_ATTEST_ALLOW_DEVELOPMENT", True)
    assert client.post("/gas/ios", json=ios_body(apple, client, **dev)).status_code == 200


def test_ios_refuses_a_chain_from_another_root(client, sends):
    # Not the `apple` fixture: the verifier keeps Apple's real root, so a chain
    # from any other CA must fail.
    from tests.conftest import FakeAppleCA

    challenge = get_challenge(client)
    key_id, att = FakeAppleCA().attest(challenges.bound_digest(challenge, ADDRESS))
    body = {"address": ADDRESS, "challenge": challenge, "key_id": key_id,
            "attestation": base64.b64encode(att).decode()}
    assert client.post("/gas/ios", json=body).status_code == 403
    assert sends == []


def test_ios_garbage_is_refused_not_crashed(apple, client, sends):
    body = ios_body(apple, client)
    body["attestation"] = base64.b64encode(b"\xff\x00not cbor").decode()
    assert client.post("/gas/ios", json=body).status_code == 403


# --- limits and send outcomes ---------------------------------------------------

def test_per_address_limit(apple, client, sends, monkeypatch):
    monkeypatch.setattr(config, "GRANT_MAX_PER_ADDRESS_PER_DAY", 1)
    assert client.post("/gas/ios", json=ios_body(apple, client)).status_code == 200
    assert client.post("/gas/ios", json=ios_body(apple, client)).status_code == 429
    assert client.post("/gas/ios", json=ios_body(apple, client, address=OTHER)).status_code == 200


def test_daily_limit(apple, client, sends, monkeypatch):
    monkeypatch.setattr(config, "GRANT_MAX_PER_DAY", 1)
    assert client.post("/gas/ios", json=ios_body(apple, client)).status_code == 200
    assert client.post("/gas/ios", json=ios_body(apple, client, address=OTHER)).status_code == 429


def test_failed_send_does_not_count(apple, client, monkeypatch):
    monkeypatch.setattr(config, "GRANT_MAX_PER_ADDRESS_PER_DAY", 1)

    async def boom(address):
        raise RuntimeError("node down")

    monkeypatch.setattr(chain, "send_dust", boom)
    assert client.post("/gas/ios", json=ios_body(apple, client)).status_code == 502

    async def ok(address):
        return "HASH"

    monkeypatch.setattr(chain, "send_dust", ok)
    assert client.post("/gas/ios", json=ios_body(apple, client)).status_code == 200


def test_unresolved_send_is_pending(apple, client, monkeypatch):
    async def unresolved(address):
        raise chain.SendUnresolved("ABC", TimeoutError())

    monkeypatch.setattr(chain, "send_dust", unresolved)
    resp = client.post("/gas/ios", json=ios_body(apple, client))
    assert resp.status_code == 202
    assert resp.json()["tx_hash"] == "ABC"


# --- Android ----------------------------------------------------------------------

def android_body(client, google, address=ADDRESS, **kwargs):
    challenge = get_challenge(client, address)
    chain_b64 = google.attest(challenges.bound_digest(challenge, address), **kwargs)
    return {"address": address, "challenge": challenge, "chain": chain_b64}


def test_android_grant(client, google, sends):
    resp = client.post("/gas/android", json=android_body(client, google))
    assert resp.status_code == 200, resp.text
    assert sends == [ADDRESS]


def test_android_app_id_may_be_hardware_enforced(client, google, sends):
    assert client.post("/gas/android", json=android_body(client, google, app_id_in_hardware=True)).status_code == 200


@pytest.mark.parametrize("kwargs", [
    {"package": "com.evil"},
    {"digests": (b"\x01" * 32,)},
    {"digests": (b"\x01" * 32, SIGNING_DIGEST)},
    {"security": 0},
    {"locked": False},
    {"boot": 2},
    {"origin": 2},
])
def test_android_refuses_a_bad_attestation(client, google, sends, kwargs):
    assert client.post("/gas/android", json=android_body(client, google, **kwargs)).status_code == 403
    assert sends == []


def test_android_attestation_cannot_be_moved_to_another_address(client, google, sends):
    body = android_body(client, google)
    body["challenge"] = get_challenge(client, OTHER)
    body["address"] = OTHER
    assert client.post("/gas/android", json=body).status_code == 403
    assert sends == []


def test_android_unlocked_bootloader_is_configurable(client, google, sends, monkeypatch):
    monkeypatch.setattr(config, "ANDROID_REQUIRE_LOCKED_BOOTLOADER", False)
    assert client.post("/gas/android", json=android_body(client, google, locked=False)).status_code == 200


def test_android_refuses_a_chain_from_another_root(client, google, sends):
    challenge = get_challenge(client)
    body = {"address": ADDRESS, "challenge": challenge,
            "chain": FakeGoogleCA().attest(challenges.bound_digest(challenge, ADDRESS))}
    assert client.post("/gas/android", json=body).status_code == 403


def test_android_refuses_a_revoked_intermediate(client, google, sends):
    google.revoked.add(format(google.inter.serial_number, "x"))
    assert client.post("/gas/android", json=android_body(client, google)).status_code == 403


def test_android_refuses_a_spliced_chain(client, google, sends):
    # A leaf from one chain presented with another chain's intermediate.
    body = android_body(client, google)
    body["chain"][1] = FakeGoogleCA().attest(b"x" * 32)[1]
    assert client.post("/gas/android", json=body).status_code == 403


def test_android_garbage_is_refused_not_crashed(client, google, sends):
    body = android_body(client, google)
    body["chain"] = [base64.b64encode(b"not a certificate").decode()] * 3
    assert client.post("/gas/android", json=body).status_code == 403


def test_android_off_without_signing_certs(client, sends, monkeypatch):
    monkeypatch.setattr(config, "ANDROID_SIGNING_CERT_SHA256", frozenset())
    body = {"address": ADDRESS, "challenge": get_challenge(client), "chain": []}
    assert client.post("/gas/android", json=body).status_code == 503
