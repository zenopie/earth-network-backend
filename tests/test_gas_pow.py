"""The proof of work /gas/register asks for (services/pow): the stamp spec
wallets implement, GET /gas/pow, difficulty, and when a stamp is consumed or
given back.
"""
import config
from services import dsccommit, gascheck, knowndsc, pow, ratelimit
from services.zk import privacy
from tests.gas_fixtures import DSC_KEY, NOT_CHAINED, body, post, post_as, with_pow


def test_the_stamp_spec():
    """Pinned so wallets can test against it."""
    inp = pow.stamp_input(1759363200, "123", "456", "1f")
    assert inp == b"earth-gas-pow/v1:1759363200:123:456:1f"
    assert pow.leading_zero_bits(b"\x00\x0f" + b"\xff" * 30) == 12
    nonce = pow.solve(1759363200, "123", "456", 8)
    bits, _ = pow.check(1759363200, nonce, "123", "456", now=1759363200)
    assert bits >= 8


def test_pow_endpoint_describes_the_stamp(client):
    p = client.get("/gas/pow").json()
    assert p["version"] == pow.VERSION and p["algorithm"] == "sha256"
    assert p["bits"] == p["reserved_bits"] and p["shedding"] is False
    assert p["input"] == f"{pow.VERSION}:<ts>:<public_signals[1]>:<public_signals[2]>:<nonce>"


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


def test_gas_pow_says_what_a_shed_client_needs(client, chain):
    for i in range(3):
        chain["refuse"][7300 + i] = NOT_CHAINED
        assert post_as(client, body(7300 + i, dsc=1), "100.64.0.2").status_code == 403
    shed = client.get("/gas/pow", headers={"cf-connecting-ip": "100.64.0.2"}).json()
    assert shed["shedding"] is True and shed["bits"] == shed["shedding_bits"]
    other = client.get("/gas/pow", headers={"cf-connecting-ip": "100.64.0.3"}).json()
    assert other["shedding"] is False and other["bits"] == other["reserved_bits"]


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


def test_a_stamp_is_consumed_before_the_lane_commitment_await(client, chain, monkeypatch):
    """Concurrent copies of one request each passed pow.check() while the
    first awaited lane_commitment, so one stamp admitted several priority
    checks. Now it is consumed before the await."""
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    req = with_pow(body(7600), config.POW_RESERVED_BITS)
    stamp = req["pow"]
    signals = req["public_signals"]
    seen_during_await = []
    real = dsccommit.lane_commitment

    async def lane(der):
        try:
            pow.check(stamp["ts"], stamp["nonce"], signals[config.PASSPORT_ADDRESS_INDEX],
                      signals[config.PASSPORT_NULLIFIER_INDEX])
            seen_during_await.append(False)
        except pow.Rejected:
            seen_during_await.append(True)
        return await real(der)

    monkeypatch.setattr(dsccommit, "lane_commitment", lane)
    assert post_as(client, req, "198.51.100.60").status_code == 200
    assert seen_during_await == [True]
    assert chain["priority"][-1] is True


def test_a_stamp_not_relied_on_is_given_back(client, chain, monkeypatch):
    """A candidate whose signer lane is taken goes to the ordinary lane; the
    stamp it consumed early is given back for the wallet to use again."""
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    assert ratelimit.take_signer_lane(dsc)
    try:
        req = with_pow(body(7700), config.POW_RESERVED_BITS)
        assert post_as(client, req, "198.51.100.61").status_code == 200
        assert chain["priority"][-1] is False
    finally:
        ratelimit.release_signer_lane(dsc)
    s = req["pow"]
    pow.check(s["ts"], s["nonce"], req["public_signals"][config.PASSPORT_ADDRESS_INDEX],
              req["public_signals"][config.PASSPORT_NULLIFIER_INDEX])  # not Rejected
