"""Audit round 5 (backend): regressions for each finding (the PoCs in
scratchpad/a5/test_poc_a5.py, now refused)."""
import base64
import os
import threading
import time

import pytest

import config
from services import dsccommit, knowndsc, ratelimit
from services.zk import privacy
from tests.test_proof_grants import DSC_DER_B64, DSC_KEY
from tests.test_queue import with_pow
from tests.test_register_dos import body, chain, post  # noqa: F401


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def rsa_cert(modulus_bytes: int, salt: bytes = b"\x01") -> str:
    """A certificate shell (unsigned) around a random RSA modulus of that many bytes."""
    modulus = b"\x7f" + os.urandom(modulus_bytes - 1)
    rsakey = _der(0x30, _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01"))
    spki = _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
                + _der(0x03, b"\x00" + rsakey))
    tbs = _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + _der(0x02, salt) + _der(0x30, b"") * 4 + spki)
    return base64.b64encode(_der(0x30, tbs + _der(0x30, b"") + _der(0x03, b"\x00"))).decode()


# --- M1: the reserved lane's DSC commitment ----------------------------------

@pytest.fixture
def hashes(monkeypatch):
    """Every commitment computed: (key bytes, thread it ran on)."""
    calls = []
    real = dsccommit.commitment_of_key

    def timed(tag, key):
        calls.append((len(key), threading.current_thread() is threading.main_thread()))
        return real(tag, key)
    monkeypatch.setattr(dsccommit, "commitment_of_key", timed)
    return calls


def test_a_key_past_rsa_4096_is_never_hashed(client, chain, hashes):
    """The PoC: fresh 2048-byte moduli, each ~0.18 s of event-loop hashing here."""
    knowndsc.set_known({privacy.field_bytes(DSC_KEY)})
    for i in range(3):
        chain["refuse"][90000 + i] = "no trusted issuing CSCA found"
        r = post(client, with_pow(body(90000 + i, der=rsa_cert(2048, os.urandom(8))), config.POW_RESERVED_BITS))
        assert r.status_code == 403
        assert chain["priority"][-1] is False, "the ordinary lane: the chain decides"
    assert hashes == []


def test_a_mismatched_key_is_refused_at_once_and_hashed_off_the_loop(client, chain, hashes):
    knowndsc.set_known({privacy.field_bytes(DSC_KEY)})
    r = post(client, with_pow(body(90100, der=rsa_cert(512)), config.POW_RESERVED_BITS))
    assert r.status_code == 400 and "dsc_der is not" in r.json()["message"]
    assert chain["priority"] == [], "never queued"
    assert hashes == [(512, False)], "hashed once, in a worker thread"


def test_the_cache_is_keyed_by_the_key_not_the_certificate(hashes):
    import asyncio

    raw = base64.b64decode(rsa_cert(256, b"\x01"))
    # The same key in another certificate (another serial): no second hash.
    other = bytearray(raw)
    i = raw.index(b"\x02\x01\x01")  # the serial
    other[i + 2] = 0x02
    first = asyncio.run(dsccommit.lane_commitment(raw))
    assert asyncio.run(dsccommit.lane_commitment(bytes(other))) == first
    assert len(hashes) == 1


def test_a_real_signer_still_takes_the_lane(client, chain, hashes):
    knowndsc.set_known({privacy.field_bytes(DSC_KEY)})
    assert post(client, with_pow(body(90200, der=DSC_DER_B64), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


# --- M3: the reserved lane per signer, refusals per client --------------------

def test_five_junk_requests_no_longer_evict_a_signers_real_registrants(client, chain):
    """The PoC: five refused requests with a signer's public certificate."""
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    for i in range(5):  # attacker: real public cert, junk proof, the work done
        chain["refuse"][91000 + i] = "invalid registration proof"
        assert post(client, with_pow(body(91000 + i), config.POW_SHED_BITS)).status_code == 403
    # A genuine registrant of the same signer, with the work done, from another IP.
    assert post(client, with_pow(body(91999), config.POW_SHED_BITS)).status_code == 200
    assert chain["priority"][-1] is True, "still the reserved lane"


def test_one_priority_check_per_signer_at_a_time(chain, monkeypatch):
    import asyncio

    import httpx

    from services import gascheck
    from tests.conftest import gas_app

    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    release = None

    async def slow(msg, priority=False):
        chain["priority"].append(priority)
        if len(chain["priority"]) == 1:
            await release.wait()
        nf = int(msg["public_signals"][2])
        return {"ok": True, "nullifier": privacy.field_bytes(nf).hex(), "switched": False}
    monkeypatch.setattr(gascheck, "registration", slow)

    async def go():
        nonlocal release
        release = asyncio.Event()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gas_app()), base_url="http://t") as c:
            def send(nf, ip):
                return c.post("/gas/register", json=with_pow(body(nf), config.POW_RESERVED_BITS),
                              headers={"cf-connecting-ip": ip})
            first = asyncio.create_task(send(92000, "198.51.100.1"))
            while not chain["priority"]:
                await asyncio.sleep(0.001)
            second = await send(92001, "198.51.100.2")  # while the first waits
            release.set()
            done = await first
            third = await send(92002, "198.51.100.3")  # after: the place is free again
            return done, second, third
    a, b, c = asyncio.run(go())
    assert (a.status_code, b.status_code, c.status_code) == (200, 200, 200)
    assert chain["priority"] == [True, False, True]
    assert not ratelimit._signer_lane


def test_the_network_budget_fits_what_the_lease_can_verify():
    # ~10 s an earthd run on 0.1 CPU, one at a time: ~6 a minute at most.
    assert 0 < config.REGISTER_REFUSALS_PER_MINUTE <= 6
    assert config.REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE <= config.REGISTER_REFUSALS_PER_MINUTE


# --- M2: one URL per page ------------------------------------------------------

from tests.test_audit4 import BASE, notes_index  # noqa: E402,F401


@pytest.mark.parametrize("query", [
    "from_pos=1000&limit=1000&cb=1",       # an unknown parameter
    "from_pos=1000&limit=1000&cb=2",
    "from_pos=0001000&limit=1000",         # leading zeros
    "from_pos=%2B1000&limit=01000",        # encoded +, leading zero
    "from_pos=+1000",
    "from_pos=%31000",                     # an encoded digit
    "from_pos=1000&from_pos=1000",         # repeated
    "from_pos=1000&limit=1000&",           # an empty pair
    "from_pos=",
    "from_pos=-0",
    "epoch=1",                             # another stream's parameter
])
def test_only_the_canonical_spelling_of_a_page_reaches_a_handler(notes_index, query):
    r = notes_index.get(f"{BASE}/notes?{query}")
    assert r.status_code == 400, query
    assert r.headers["cache-control"] == "no-store"
    assert "canonical" in r.json()["message"]


def test_the_canonical_page_is_served(notes_index):
    rows = set()
    for query in ("from_pos=1000&limit=1000", "limit=1000&from_pos=1000", "from_pos=1000", "from_pos=0"):
        r = notes_index.get(f"{BASE}/notes?{query}")
        assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
        rows.add(r.json()["notes"][0][0])
    assert rows == {1000, 0}
    assert notes_index.get(f"{BASE}/status").status_code == 200
    r = notes_index.get("/privacy/status?cb=1")
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store"
    r = notes_index.get(f"{BASE}/notes/")
    assert r.status_code == 404 and r.headers["cache-control"] == "no-store"


def test_the_gate_knows_every_privacy_route():
    from fastapi import FastAPI

    from routers import privacy as privacy_router
    from services import privacygate

    app = FastAPI()
    app.include_router(privacy_router.router)
    base = "/privacy/{chain_id}/{genesis}/"
    for path, item in app.openapi()["paths"].items():
        name = "" if path == "/privacy/status" else path[len(base):]
        assert path == "/privacy/status" or path.startswith(base)
        params = {p["name"] for p in item["get"].get("parameters", []) if p["in"] == "query"}
        assert params == set(privacygate.ENDPOINTS.get(name, frozenset())), path
    assert len(app.openapi()["paths"]) == len(privacygate.ENDPOINTS) + 1


# --- CORS on /privacy ----------------------------------------------------------

def test_privacy_names_the_web_origin_for_everyone(notes_index):
    for origin in ("https://erth.network", None, "https://evil.example"):
        h = {"origin": origin} if origin else {}
        r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers=h)
        assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
        assert r.headers["access-control-allow-origin"] == "https://erth.network", origin
        assert "access-control-allow-credentials" not in r.headers
    r = notes_index.get("/privacy/status", headers={"origin": "https://erth.network"})
    assert r.headers["access-control-allow-origin"] == "https://erth.network"
    # Refusals too, so the wallet can read the status.
    r = notes_index.get(f"{BASE}/notes?cb=1", headers={"origin": "https://erth.network"})
    assert r.status_code == 400 and r.headers["access-control-allow-origin"] == "https://erth.network"


def test_a_local_dev_origin_is_reflected_and_never_cached(notes_index):
    for origin in ("http://localhost:5173", "http://127.0.0.1:8080", "http://localhost"):
        r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers={"origin": origin})
        assert r.status_code == 200
        assert r.headers["access-control-allow-origin"] == origin
        assert r.headers["cache-control"] == "no-store"
    r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers={"origin": "http://localhost.evil.example"})
    assert r.headers["access-control-allow-origin"] == "https://erth.network"


def test_a_preflight_is_answered(notes_index):
    r = notes_index.options(f"{BASE}/notes", headers={"origin": "https://erth.network",
                                                      "access-control-request-method": "GET"})
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "https://erth.network"
    assert "GET" in r.headers["access-control-allow-methods"]


def test_no_cors_outside_privacy():
    from fastapi.testclient import TestClient

    from services.privacygate import PrivacyGate
    from tests.conftest import gas_app

    app = gas_app()
    app.add_middleware(PrivacyGate)
    r = TestClient(app).get("/gas/pow", headers={"origin": "https://erth.network"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers
