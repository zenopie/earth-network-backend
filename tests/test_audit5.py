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
