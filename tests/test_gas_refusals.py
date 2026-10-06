"""What a gas-check refusal costs: the refusal budgets (per DSC commitment,
per issuing country, network-wide), the per-client refusal budget, shedding
(a proof of work to be queued) and what refusals log.
"""
import base64
import logging

import pytest

import config
from routers import gas
from services import knowndsc, ratelimit
from services.zk import privacy
from tests.gas_fixtures import (CHEAP_REFUSALS, COUNTRY_CAP, DE, DSC_KEY, FR, NOT_CHAINED, PROOF, RATE_CAP, body,
                                post, post_as, pow_between, with_pow)
from tests.gas_fixtures import DSC_KEY as KNOWN_DSC  # reg_body's public_signals[3]


def test_refusals_that_cost_no_verification_shed_nobody(client, chain):
    """Ten junk refusals (DSC does not chain) then a real registrant."""
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


def test_the_network_budget_fits_what_the_lease_can_verify():
    # ~10 s an earthd run on 0.1 CPU, one at a time: ~6 a minute at most.
    assert 0 < config.REGISTER_REFUSALS_PER_MINUTE <= 6
    assert config.REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE <= config.REGISTER_REFUSALS_PER_MINUTE


def test_every_refusal_in_the_reserved_lane_counts(client, chain, monkeypatch):
    """A flood with the signer's real certificate: every refusal counts
    against the client, and the signer keeps its place (audit-4 B1, audit-5
    M3)."""
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 3)
    monkeypatch.setattr(config, "REGISTER_CLIENT_REFUSALS_PER_WINDOW", 3)
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    ip = {"cf-connecting-ip": "203.0.113.77"}
    for i in range(3):
        chain["refuse"][71000 + i] = CHEAP_REFUSALS[i % len(CHEAP_REFUSALS)]
        r = client.post("/gas/register", json=with_pow(body(71000 + i), config.POW_RESERVED_BITS), headers=ip)
        assert r.status_code == 403, r.text
        assert chain["priority"][-1] is True
    asked = len(chain["priority"])
    # Past its refusal budget the client is shed (audit-6 M1): the reserved
    # lane's work is not enough, the shedding difficulty's is.
    r = client.post("/gas/register", json=pow_between(body(71010), config.POW_RESERVED_BITS, config.POW_SHED_BITS),
                    headers=ip)
    assert r.status_code == 428 and "refused" in r.json()["message"]
    assert r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert len(chain["priority"]) == asked, "turned away before the queue"
    r = client.post("/gas/register", json=with_pow(body(71011), config.POW_SHED_BITS), headers=ip)
    assert r.status_code == 200, r.text
    # Counted against the client only: the network budget (3) is untouched.
    assert ratelimit.shedding(None, None) is None
    # And the signer's real registrants keep the lane.
    assert post(client, with_pow(body(71020), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


def test_cheap_reserved_lane_refusals_spend_no_signer_budget(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 3)
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    for i in range(3):
        chain["refuse"][72000 + i] = CHEAP_REFUSALS[2]
        assert post(client, with_pow(body(72000 + i), config.POW_RESERVED_BITS)).status_code == 403
    assert ratelimit.shedding(dsc, None) is None


def test_ordinary_lane_cheap_refusals_count_against_the_client(client, chain):
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    ip = {"cf-connecting-ip": "203.0.113.78"}
    codes = []
    for i in range(5):
        chain["refuse"][73000 + i] = CHEAP_REFUSALS[i % len(CHEAP_REFUSALS)]
        codes.append(client.post("/gas/register", json=body(73000 + i), headers=ip).status_code)  # no work: ordinary lane
    n = config.REGISTER_CLIENT_REFUSALS_PER_WINDOW
    assert codes == [403] * n + [428] * (5 - n)
    assert ratelimit.shedding(dsc, None) is None, "no other budget"




def test_junk_from_one_64_does_not_lock_out_its_48(client, chain):
    """Junk from three /64s of one /48 sheds only those /64s; a registrant
    on another /64 is not held up (audit-6 M1)."""
    for i in range(3):
        chain["refuse"][7000 + i] = NOT_CHAINED
        assert post_as(client, body(7000 + i, dsc=1), f"2001:db8:1:{i}::1").status_code == 403
    r = post_as(client, body(1234, dsc=555), "2001:db8:1:ffff::9")
    assert r.status_code == 200, r.text


def test_one_64s_junk_sheds_that_64_only(client, chain):
    for i in range(3):
        chain["refuse"][7200 + i] = NOT_CHAINED
        assert post_as(client, body(7200 + i, dsc=1), f"2001:db8:2:7::{i + 1}").status_code == 403
    r = post_as(client, body(7210, dsc=555), "2001:db8:2:7::99")
    assert r.status_code == 428 and r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert post_as(client, body(7211, dsc=555), "2001:db8:2:8::1").status_code == 200


def test_cgnat_ipv4_pays_through_with_work(client, chain):
    """CGNAT: everyone on the address is shed, not refused: a real
    registrant pays the shedding work and is queued (audit-6 M1)."""
    for i in range(3):
        chain["refuse"][7100 + i] = NOT_CHAINED
        assert post_as(client, body(7100 + i, dsc=1), "100.64.0.1").status_code == 403
    asked = len(chain["priority"])
    r = post_as(client, body(4321, dsc=555), "100.64.0.1")
    assert r.status_code == 428, r.text
    assert "refused registrations from this network" in r.json()["message"]
    assert r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert len(chain["priority"]) == asked, "turned away before the queue"
    r = post_as(client, with_pow(body(4322, dsc=555), config.POW_SHED_BITS), "100.64.0.1")
    assert r.status_code == 200, r.text
    # Junk still costs work per request, and a stamp is used once.
    chain["refuse"][7110] = NOT_CHAINED
    junk = with_pow(body(7110, dsc=1), config.POW_SHED_BITS)
    assert post_as(client, junk, "100.64.0.1").status_code == 403
    assert post_as(client, junk, "100.64.0.1").status_code == 428


def test_a_daily_cap_does_not_count_against_the_client(client, chain):
    for i in range(5):
        chain["refuse"][7400 + i] = RATE_CAP
        assert post_as(client, body(7400 + i, dsc=555), "100.64.0.4").status_code == 403
    assert not ratelimit.client_refused_out(ratelimit.refusal_key("100.64.0.4"))
    assert post_as(client, body(7410, dsc=555), "100.64.0.4").status_code == 200


def test_client_refusals_age_out(monkeypatch):
    monkeypatch.setattr(config, "REGISTER_CLIENT_REFUSALS_PER_WINDOW", 3)
    for _ in range(3):
        ratelimit.note_client_refusal("c", now=1000.0)
    assert ratelimit.client_refused_out("c", now=1001.0)
    assert not ratelimit.client_refused_out("d", now=1001.0)
    assert not ratelimit.client_refused_out("c", now=1000.0 + 2 * config.REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS + 1)


@pytest.mark.parametrize("error,kind", [
    ("identity tree full", "tree full"),  # 1120
    ('affiliate_handle "x": affiliate_handle is not a live handle', "affiliate"),  # 1121
    ("passport is already registered to this identity commitment", "replay"),  # 1123
    ("this registration has already been used", "binding used"),  # 1124
    ("identity switch must be proven under the live registration's document signer", "switch signer"),  # 1127
    ("proof dated 1790000000, live registration proven 1790000000: identity switch must be proven on a later date "
     "than the live registration", "switch stale"),  # 1128
    ("verification failed: invalid move proof", "move"),  # 1129
    ("this identity moved its handle away", "move"),  # 1125
    ("this identity moved its caretaker split away", "move"),  # 1126
])
def test_refusal_kinds_of_the_new_codes(error, kind):
    from routers import gas
    assert gas._refusal_kind(error) == kind


def test_a_move_refusal_is_not_an_invalid_registration_proof_nor_user_state():
    from routers import gas
    assert gas._refusal_kind("invalid move proof") != gas._refusal_kind("invalid registration proof")
    assert "move" not in gas._USER_STATE_KINDS


def test_a_switch_under_another_signer_counts_against_the_client():
    # 1127 is refused before the proof is verified: anyone can mint it from a
    # live nullifier and any chaining DSC, so it is not user state.
    from routers import gas
    assert "switch signer" not in gas._USER_STATE_KINDS


def test_a_same_day_switch_says_retry_tomorrow(client, chain):
    # 1128 is checked before the proof too (a live nullifier, its public DSC
    # and a junk proof dated no later mint it), so it counts against the
    # client; the reply tells a real holder when to come back.
    assert "switch stale" not in gas._USER_STATE_KINDS
    chain["refuse"][902] = ("proof dated 1790000000, live registration proven 1790000000: identity switch must be "
                            "proven on a later date than the live registration")
    r = post(client, body(902))
    assert r.status_code == 403 and "retry tomorrow (UTC)" in r.json()["message"]


def test_refusal_logs_name_neither_affiliate_nor_country(client, chain, caplog):
    affiliate = "amy-the-referrer"
    caplog.set_level(logging.DEBUG)
    chain["refuse"][900] = f'affiliate_handle "{affiliate}": affiliate_handle is not a live handle'
    chain["refuse"][901] = COUNTRY_CAP
    assert post(client, body(900)).status_code == 403
    assert post(client, body(901, der=DE)).status_code == 403
    ours = [r.getMessage() for r in caplog.records if r.name == "routers.gas"]
    assert ours == ["registration check refused: affiliate", "registration check refused: rate cap"]
    assert affiliate not in caplog.text


def test_dsc_country_reads_the_issuer():
    assert gas._dsc_country(base64.b64decode(DE)) == "DE"
    assert gas._dsc_country(b"x") is None


def test_coarse_cuts_decimal_signals():
    nf = "20721221850428050168833700122818390286788073887706614806955557958870761234"
    out = gas._coarse(f"nullifier {nf} refused; 1121 at height 52000")
    assert nf[:16] not in out and "<hex>" in out and "1121" in out and "52000" in out
