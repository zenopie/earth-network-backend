"""/gas/register under junk (audit 3): what spends a refusal budget, whose
budget it spends, the reserved lane's cooldown and proof of work.

poc_refusal_budget_dos.py: ten junk requests a minute from ten addresses,
refused by gas-check because their DSC did not chain, spent the one global
budget, and every real registrant outside the reserved lane got 429; junk
copying a known (public) DSC commitment still went to the reserved lane.
"""
import base64
import datetime
import logging
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config
from routers import gas
from services import gascheck, knowndsc, pow, ratelimit
from services.zk import privacy
from tests.test_proof_grants import reg_body, signals
from tests.test_queue import weak_pow, with_pow

from tests.test_proof_grants import DSC_KEY as KNOWN_DSC  # reg_body's public_signals[3]


def dsc_cert(country: str) -> str:
    """A throwaway certificate whose issuer is C=<country>, base64 DER."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                      x509.NameAttribute(NameOID.COMMON_NAME, "test DSC")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


DE, FR = dsc_cert("DE"), dsc_cert("FR")


def body(nf: int, dsc: int = KNOWN_DSC, der: str | None = None) -> dict:
    b = reg_body(nf=nf)
    s = signals(nf)
    s[3] = str(dsc)
    b["public_signals"] = s
    if der is not None:
        b["dsc_der"] = der
    return b


@pytest.fixture
def chain(monkeypatch):
    """gas-check stand-in: nullifiers in `refuse` get that error; records priority."""
    state = {"refuse": {}, "priority": []}

    async def registration(msg, priority=False):
        nf = int(msg["public_signals"][2])
        state["priority"].append(priority)
        if nf in state["refuse"]:
            return {"ok": False, "error": state["refuse"][nf]}
        return {"ok": True, "nullifier": privacy.field_bytes(nf).hex(), "switched": False}

    async def shield(pc, ct):
        return "HASH"

    monkeypatch.setattr(gascheck, "registration", registration)
    monkeypatch.setattr(gas.chain, "shield_dust", shield)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    monkeypatch.setattr(config, "POW_RESERVED_BITS", 6)
    monkeypatch.setattr(config, "POW_SHED_BITS", 8)
    monkeypatch.setattr(config, "POW_LOAD_EXTRA_BITS", 0)
    return state


_ip = iter(range(1, 10**6))


def post(client, b):
    i = next(_ip)
    return client.post("/gas/register", json=b, headers={"cf-connecting-ip": f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"})


PROOF = "invalid registration proof"
NOT_CHAINED = "no trusted issuing CSCA found"
COUNTRY_CAP = "country DE has reached its 100 registrations for today; retry tomorrow: " \
              "daily registration limit reached for this document signer or country"


def test_refusals_that_cost_no_verification_shed_nobody(client, chain):
    """The PoC: ten junk refusals (DSC does not chain) then a real registrant."""
    for i in range(10):
        chain["refuse"][9000 + i] = NOT_CHAINED
        assert post(client, body(9000 + i, dsc=123456)).status_code == 403
    assert ratelimit.shedding() is None
    assert post(client, body(1111, dsc=555)).status_code == 200


def test_a_countrys_daily_cap_sheds_nobody(client, chain):
    for i in range(20):
        chain["refuse"][100 + i] = COUNTRY_CAP
        assert post(client, body(100 + i, der=DE)).status_code == 403
    assert ratelimit.shedding(privacy.field_bytes(KNOWN_DSC), "DE") is None
    assert post(client, body(1, der=DE)).status_code == 200


def test_junk_copying_a_known_dsc_needs_work_for_the_reserved_lane(client, chain):
    knowndsc.set_known({privacy.field_bytes(KNOWN_DSC)})
    assert post(client, body(1)).status_code == 200
    assert chain["priority"][-1] is False, "no proof of work: the ordinary lane"
    assert post(client, weak_pow(body(2), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is False, "too little work: the ordinary lane"
    assert post(client, with_pow(body(3), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


def test_the_budget_is_per_signer(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 3)
    for i in range(3):
        chain["refuse"][200 + i] = PROOF
        assert post(client, body(200 + i, dsc=41)).status_code == 403
    # Signer 41 is shed: work, or 428 before the queue.
    r = post(client, body(300, dsc=41))
    assert r.status_code == 428 and r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert post(client, with_pow(body(301, dsc=41), config.POW_SHED_BITS)).status_code == 200
    # Another signer's registrants are not.
    assert post(client, body(302, dsc=42)).status_code == 200


def test_the_budget_is_per_country(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 0)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE", 3)
    for i in range(3):
        chain["refuse"][400 + i] = PROOF
        assert post(client, body(400 + i, dsc=50 + i, der=DE)).status_code == 403
    assert post(client, body(410, dsc=60, der=DE)).status_code == 428
    assert post(client, body(411, dsc=61, der=FR)).status_code == 200


def test_the_network_backstop(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 4)
    for i in range(4):
        chain["refuse"][500 + i] = PROOF
        assert post(client, body(500 + i, dsc=70 + i)).status_code == 403
    assert post(client, body(510, dsc=99)).status_code == 428
    assert client.get("/gas/pow").json()["shedding"] is True


def test_a_dsc_named_by_failures_leaves_the_reserved_lane(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 0)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 0)
    monkeypatch.setattr(config, "REGISTER_DSC_FAILURES_BEFORE_COOLDOWN", 3)
    knowndsc.set_known({privacy.field_bytes(KNOWN_DSC)})
    for i in range(3):
        chain["refuse"][600 + i] = PROOF
        assert post(client, with_pow(body(600 + i), config.POW_RESERVED_BITS)).status_code == 403
        assert chain["priority"][-1] is True
    assert ratelimit.dsc_cooling(privacy.field_bytes(KNOWN_DSC))
    assert post(client, with_pow(body(610), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is False, "cooling down: the ordinary lane"


def test_the_cooldown_ages_out():
    dsc = b"\x01" * 32
    for _ in range(config.REGISTER_DSC_FAILURES_BEFORE_COOLDOWN):
        ratelimit.note_refusal(dsc, None, now=1000.0)
    assert ratelimit.dsc_cooling(dsc, now=1001.0)
    assert not ratelimit.dsc_cooling(dsc, now=1000.0 + 2 * config.REGISTER_DSC_COOLDOWN_SECONDS + 1)


def test_a_stamp_is_used_once_and_must_be_fresh(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 1)
    ratelimit.note_refusal()
    b = with_pow(body(700), config.POW_SHED_BITS)
    chain["refuse"][700] = "passport expired"
    assert post(client, b).status_code == 403
    r = post(client, b)
    assert r.status_code == 428 and "already used" in r.json()["message"]
    stale = dict(b, pow={"ts": b["pow"]["ts"] - config.POW_MAX_AGE_SECONDS - 5, "nonce": b["pow"]["nonce"]})
    r = post(client, stale)
    assert r.status_code == 428 and "too far" in r.json()["message"]


def test_a_stamp_is_given_back_when_the_check_never_ran(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 1)
    ratelimit.note_refusal()
    real = gascheck.registration

    async def down(msg, priority=False):
        raise gascheck.Unavailable("node down")
    b = with_pow(body(800), config.POW_SHED_BITS)
    monkeypatch.setattr(gascheck, "registration", down)
    assert post(client, b).status_code == 503
    monkeypatch.setattr(gascheck, "registration", real)
    assert post(client, b).status_code == 200, "the same stamp is good again"


def test_difficulty_rises_with_load(monkeypatch):
    monkeypatch.setattr(config, "POW_RESERVED_BITS", 16)
    monkeypatch.setattr(config, "POW_SHED_BITS", 20)
    monkeypatch.setattr(config, "POW_LOAD_EXTRA_BITS", 2)
    monkeypatch.setattr(config, "POW_MAX_BITS", 21)
    monkeypatch.setattr(gascheck, "_waiting", 0)
    assert pow.required_bits(shedding=False) == 16
    monkeypatch.setattr(gascheck, "_waiting", config.GAS_CHECK_MAX_WAITING)
    assert pow.required_bits(shedding=False) == 18
    assert pow.required_bits(shedding=True) == 21, "capped"


def test_pow_endpoint_describes_the_stamp(client):
    p = client.get("/gas/pow").json()
    assert p["version"] == pow.VERSION and p["algorithm"] == "sha256"
    assert p["bits"] == p["reserved_bits"] and p["shedding"] is False
    assert p["input"] == f"{pow.VERSION}:<ts>:<public_signals[1]>:<public_signals[2]>:<nonce>"


def test_the_stamp_spec():
    """Pinned so wallets can test against it."""
    inp = pow.stamp_input(1759363200, "123", "456", "1f")
    assert inp == b"earth-gas-pow/v1:1759363200:123:456:1f"
    assert pow.leading_zero_bits(b"\x00\x0f" + b"\xff" * 30) == 12
    nonce = pow.solve(1759363200, "123", "456", 8)
    bits, _ = pow.check(1759363200, nonce, "123", "456", now=1759363200)
    assert bits >= 8


def test_refusal_logs_name_neither_affiliate_nor_country(client, chain, caplog):
    affiliate = "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"
    caplog.set_level(logging.DEBUG)
    chain["refuse"][900] = f"affiliate {affiliate}: affiliate holds no live referrer binding"
    chain["refuse"][901] = COUNTRY_CAP
    assert post(client, body(900)).status_code == 403
    assert post(client, body(901, der=DE)).status_code == 403
    ours = [r.getMessage() for r in caplog.records if r.name == "routers.gas"]
    assert ours == ["registration check refused: affiliate", "registration check refused: rate cap"]
    assert affiliate not in caplog.text


def test_dsc_country_reads_the_issuer():
    assert gas._dsc_country(base64.b64decode(DE)) == "DE"
    assert gas._dsc_country(b"x") is None
