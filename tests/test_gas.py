"""The grant endpoints: what an attestation must prove before dust moves."""
import base64
import time

import pytest

import config
from services import appattest, challenges, chain, playintegrity
from tests.conftest import ADDRESS, get_challenge

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
        __import__("hashlib").sha256(bytes(32) + b"earth1test").hexdigest()
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

def verdict(nonce, **over):
    payload = {
        "requestDetails": {"requestPackageName": config.ANDROID_PACKAGE, "nonce": nonce,
                           "timestampMillis": str(int(time.time() * 1000))},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": config.ANDROID_PACKAGE},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
    }
    for path, value in over.items():
        section, field = path.split(".")
        payload[section][field] = value
    return payload


@pytest.fixture
def google(monkeypatch):
    """Play Integrity configured, with decode answering whatever the test sets."""
    monkeypatch.setattr(config, "GOOGLE_SERVICE_ACCOUNT_JSON", "{}")
    state = {"payload": None}

    async def decode(token):
        assert token == "TOKEN"
        return state["payload"]

    monkeypatch.setattr(playintegrity, "decode", decode)
    return state


def android_body(client, google, address=ADDRESS, **over):
    challenge = get_challenge(client, address)
    nonce = challenges.b64url_encode(challenges.bound_digest(challenge, address))
    google["payload"] = verdict(nonce, **over)
    return {"address": address, "challenge": challenge, "token": "TOKEN"}


def test_android_grant(client, google, sends):
    resp = client.post("/gas/android", json=android_body(client, google))
    assert resp.status_code == 200, resp.text
    assert sends == [ADDRESS]


@pytest.mark.parametrize("over", [
    {"requestDetails.requestPackageName": "com.evil"},
    {"requestDetails.nonce": "AAAA"},
    {"requestDetails.timestampMillis": "1000"},
    {"appIntegrity.appRecognitionVerdict": "UNRECOGNIZED_VERSION"},
    {"appIntegrity.packageName": "com.evil"},
    {"deviceIntegrity.deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]},
])
def test_android_refuses_a_bad_verdict(client, google, sends, over):
    assert client.post("/gas/android", json=android_body(client, google, **over)).status_code == 403
    assert sends == []


def test_android_sideload_allowance(client, google, sends, monkeypatch):
    monkeypatch.setattr(config, "PLAY_INTEGRITY_ALLOW_UNRECOGNIZED", True)
    body = android_body(client, google, **{"appIntegrity.appRecognitionVerdict": "UNRECOGNIZED_VERSION"})
    assert client.post("/gas/android", json=body).status_code == 200


def test_android_off_without_a_service_account(client, sends, monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_SERVICE_ACCOUNT_JSON", "")
    body = {"address": ADDRESS, "challenge": get_challenge(client), "token": "TOKEN"}
    assert client.post("/gas/android", json=body).status_code == 503
