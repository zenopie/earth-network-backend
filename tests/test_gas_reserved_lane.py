"""The reserved lane: a new passport from a Document Signer the chain already
holds registrations from (services/knowndsc), with a proof of work and a
dsc_der whose DSC commitment (services/dsccommit, pinned to the chain) is the
one public_signals names; at most one priority check per signer at a time.
"""
import asyncio
import base64
import os
import threading

import pytest

import config
from services import dsccommit, knowndsc, ratelimit
from services.zk import privacy
from tests.gas_fixtures import DE, DSC_DER_B64, DSC_KEY, PROOF, body, post, rsa_cert, weak_pow, with_pow
from tests.gas_fixtures import DSC_KEY as KNOWN_DSC  # reg_body's public_signals[3]


_DSC = os.path.join(os.path.dirname(__file__), "fixtures", "dsc")


# x/pki/certs.DscCommitmentOf over each certificate, from the chain's own code
# (csca_*: x/pki/certs/testdata; dsc_*: generated here). Brainpool and the
# explicit-parameter P-521 are what `cryptography` cannot load.
@pytest.mark.parametrize("name,want", [
    ("csca_brainpoolP256r1.der", "268948bb8e64736bdc99290b15d54e82cc588b2cf5d4fe89c7aa2f4c70d51a56"),
    ("csca_brainpoolP512r1.der", "09832cfbab77ee97dbfabee18ea29b8bf65854c92bc94b9f17f62bed01bbfcae"),
    ("csca_p521_explicit.der", "2f266d7247853a1d5b98df816ed33aa115d36a7cf087a6093b036ce2fb7c85a1"),
    ("csca_rsa.der", "2ecda8196bac5e9a080b923ca19342ce73a89e5427e7ec6e5cba35df8e365086"),
    ("dsc_p256.der", "304606d727af8b6715f57c615779a33f1b00c00a1c5f50b7dd704b57a62ace59"),
    ("dsc_p384.der", "25f951db441d4b3dec429c70838a5d682a20426fb81f7e03df5aed44b1332584"),
    ("dsc_rsa2048.der", "24da980d2a1a8871a26637ced0ad8ecf0fc8191612bd12f7896b6441c0964f9c"),
    # From the mobile repo's synthetic passports (circuits/fixtures): P-224,
    # brainpoolP224r1 with explicit parameters, RSA-4096 with e = 3.
    ("dsc_p224.der", "19cbc3f8c4673334df0437153fe53e9fbb44d9b84b295fc6f07ab1a92954febf"),
    ("dsc_bp224_explicit.der", "0c012738256f4f69f517d0fb1edc9010560dc75dd4a0c6eab747189e1395c8c9"),
    ("dsc_rsa4096_e3.der", "2a91118ff73976a04c903bad487d26904ed28796062c14444e57cd1690b84e1b"),
])
def test_dsc_commitment_matches_the_chain(name, want):
    with open(os.path.join(_DSC, name), "rb") as f:
        assert dsccommit.commitment(f.read()).hex() == want


def test_dsc_commitment_matches_the_circuit():
    """zk/ultrahonk/testdata/lean_poa: dsc_pubkey -> expected_dsc_key (P-256, tag 1)."""
    key = bytes.fromhex("75c72e3b24013b813e7ee78da1fcf7cd1ac902030ea119b86df9822eddcaac49"
                        "a8a3b10d8765588476ed35eb6141681534bb7164a2fa9d6c7dd82140776c471d")
    assert int.from_bytes(dsccommit.commitment_of_key((dsccommit.TAG_P256,), key), "big") == \
        17137993880610033746992863696376072247659308979702652622358731864446692122039


@pytest.mark.parametrize("der", [b"", b"AAAA", b"\x30\x03\x02\x01\x01", b"\x30\x84\xff\xff\xff\xff"])
def test_junk_has_no_commitment(der):
    assert dsccommit.commitment(der) is None


def test_curve_constants_match_ecdsa():
    import ecdsa

    for c, oid in [(ecdsa.NIST256p, "1.2.840.10045.3.1.7"), (ecdsa.NIST384p, "1.3.132.0.34"),
                   (ecdsa.NIST521p, "1.3.132.0.35"), (ecdsa.BRAINPOOLP256r1, "1.3.36.3.3.2.8.1.1.7"),
                   (ecdsa.BRAINPOOLP384r1, "1.3.36.3.3.2.8.1.1.11"), (ecdsa.BRAINPOOLP512r1, "1.3.36.3.3.2.8.1.1.13"),
                   (ecdsa.NIST224p, "1.3.132.0.33"), (ecdsa.BRAINPOOLP224r1, "1.3.36.3.3.2.8.1.1.5")]:
        _, p, a, b, gx, gy, n = dsccommit._CURVES[oid]
        g = c.generator
        assert (p, a % p, b, gx, gy, n) == (c.curve.p(), c.curve.a() % p, c.curve.b(), g.x(), g.y(), c.order), c.name


def test_known_dsc_set_parses_the_store_subspace():
    from tests.privacy_fixtures import _field, _varint

    def pair(key, value):
        p = _field(1, key) + _field(2, value)
        return _varint(1 << 3 | 2) + _varint(len(p)) + p

    a, b, c = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    value = (pair(b"regs_by_dsc" + a, (3).to_bytes(8, "big")) + pair(b"regs_by_dsc" + b, (0).to_bytes(8, "big"))
             + pair(b"regs_by_dsc" + b"\x04" * 31, (1).to_bytes(8, "big")) + pair(b"regs_by_country" + c, b"\x00" * 7 + b"\x01"))

    class RPC:
        async def abci_query(self, path, data=b"", height=None):
            assert path == "/store/personhood/subspace" and data == b"regs_by_dsc"
            return value

    assert asyncio.run(knowndsc.refresh(RPC())) == 1
    assert knowndsc.is_known(a) and not knowndsc.is_known(b) and not knowndsc.is_known(c)


def test_junk_copying_a_known_dsc_needs_work_for_the_reserved_lane(client, chain):
    knowndsc.set_known({privacy.field_bytes(KNOWN_DSC)})
    assert post(client, body(1)).status_code == 200
    assert chain["priority"][-1] is False, "no proof of work: the ordinary lane"
    assert post(client, weak_pow(body(2), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is False, "too little work: the ordinary lane"
    assert post(client, with_pow(body(3), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


def test_a_copied_commitment_without_its_certificate_gets_no_priority(client, chain, monkeypatch):
    """A known commitment beside junk (or another signer's) dsc_der (audit-4 B1)."""
    knowndsc.set_known({privacy.field_bytes(DSC_KEY)})
    r = post(client, with_pow(body(70000, der="AAAA"), config.POW_RESERVED_BITS))
    assert r.status_code == 200
    assert chain["priority"][-1] is False, "no commitment (not a certificate): the ordinary lane"
    # Another signer's certificate: refused before the queue (audit-5 M1).
    asked = len(chain["priority"])
    r = post(client, with_pow(body(70001, der=DE), config.POW_RESERVED_BITS))
    assert r.status_code == 400 and "dsc_der is not" in r.json()["message"]
    assert len(chain["priority"]) == asked
    assert post(client, with_pow(body(70010, der=DSC_DER_B64), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


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
    """Fresh 2048-byte moduli, each ~0.18 s of hashing here, are never hashed (audit-5 M1)."""
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


def test_failures_naming_a_dsc_never_take_it_out_of_the_reserved_lane(client, chain, monkeypatch):
    """Failures naming a signer never demote it: anyone could trigger that
    with its public certificate (audit-5 M3). Failed proofs shed
    the signer (work at the shedding difficulty), and the lane stays."""
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 0)
    knowndsc.set_known({privacy.field_bytes(KNOWN_DSC)})
    for i in range(5):
        chain["refuse"][600 + i] = PROOF
        assert post(client, with_pow(body(600 + i), config.POW_SHED_BITS)).status_code == 403
        assert chain["priority"][-1] is True
    assert ratelimit.shedding(privacy.field_bytes(KNOWN_DSC)) == "signer"
    assert post(client, with_pow(body(610), config.POW_SHED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


def test_five_junk_requests_no_longer_evict_a_signers_real_registrants(client, chain):
    """Five refused requests with a signer's public certificate (audit-5 M3)."""
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
    from tests.gas_fixtures import gas_app

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
