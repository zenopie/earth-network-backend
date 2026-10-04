"""Audit round 6 (backend).

M1: three cheap refusals from one subscriber on a carrier /48, or from
anyone behind a CGNAT IPv4 address, refused everyone there 429 for an hour,
with no way to pay through (scratchpad poc/test_poc_shared_lockout.py).
Now refusals count per /64, a client past its budget is shed (a proof of
work at POW_SHED_BITS) rather than refused, and a daily cap or an expired
document signer does not count.
"""
import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config
from routers import gas
from services import dsccommit, knowndsc, pow, ratelimit
from services.zk import privacy
from tests.test_proof_grants import DSC_KEY
from tests.test_queue import with_pow
from tests.test_register_dos import NOT_CHAINED, body, chain  # noqa: F401

RATE_CAP = "dsc 0a: daily registration limit reached for this document signer or country"


def _post(client, b, ip):
    return client.post("/gas/register", json=b, headers={"cf-connecting-ip": ip})


def test_junk_from_one_64_does_not_lock_out_its_48(client, chain):
    """The auditor's scenario, IPv6: junk from three /64s of one /48 now
    sheds only those /64s; a registrant on another /64 is not held up."""
    for i in range(3):
        chain["refuse"][7000 + i] = NOT_CHAINED
        assert _post(client, body(7000 + i, dsc=1), f"2001:db8:1:{i}::1").status_code == 403
    r = _post(client, body(1234, dsc=555), "2001:db8:1:ffff::9")
    assert r.status_code == 200, r.text


def test_one_64s_junk_sheds_that_64_only(client, chain):
    for i in range(3):
        chain["refuse"][7200 + i] = NOT_CHAINED
        assert _post(client, body(7200 + i, dsc=1), f"2001:db8:2:7::{i + 1}").status_code == 403
    r = _post(client, body(7210, dsc=555), "2001:db8:2:7::99")
    assert r.status_code == 428 and r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert _post(client, body(7211, dsc=555), "2001:db8:2:8::1").status_code == 200


def test_cgnat_ipv4_pays_through_with_work(client, chain):
    """The auditor's scenario, CGNAT: everyone on the address is shed, not
    refused: a real registrant pays the shedding work and is queued."""
    for i in range(3):
        chain["refuse"][7100 + i] = NOT_CHAINED
        assert _post(client, body(7100 + i, dsc=1), "100.64.0.1").status_code == 403
    asked = len(chain["priority"])
    r = _post(client, body(4321, dsc=555), "100.64.0.1")
    assert r.status_code == 428, r.text
    assert "refused registrations from this network" in r.json()["message"]
    assert r.json()["pow"]["bits"] == config.POW_SHED_BITS
    assert len(chain["priority"]) == asked, "turned away before the queue"
    r = _post(client, with_pow(body(4322, dsc=555), config.POW_SHED_BITS), "100.64.0.1")
    assert r.status_code == 200, r.text
    # Junk still costs work per request, and a stamp is used once.
    chain["refuse"][7110] = NOT_CHAINED
    junk = with_pow(body(7110, dsc=1), config.POW_SHED_BITS)
    assert _post(client, junk, "100.64.0.1").status_code == 403
    assert _post(client, junk, "100.64.0.1").status_code == 428


def test_gas_pow_says_what_a_shed_client_needs(client, chain):
    for i in range(3):
        chain["refuse"][7300 + i] = NOT_CHAINED
        assert _post(client, body(7300 + i, dsc=1), "100.64.0.2").status_code == 403
    shed = client.get("/gas/pow", headers={"cf-connecting-ip": "100.64.0.2"}).json()
    assert shed["shedding"] is True and shed["bits"] == shed["shedding_bits"]
    other = client.get("/gas/pow", headers={"cf-connecting-ip": "100.64.0.3"}).json()
    assert other["shedding"] is False and other["bits"] == other["reserved_bits"]


def test_a_daily_cap_does_not_count_against_the_client(client, chain):
    for i in range(5):
        chain["refuse"][7400 + i] = RATE_CAP
        assert _post(client, body(7400 + i, dsc=555), "100.64.0.4").status_code == 403
    assert not ratelimit.client_refused_out(ratelimit.refusal_key("100.64.0.4"))
    assert _post(client, body(7410, dsc=555), "100.64.0.4").status_code == 200


def _expired_cert() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")])
    t = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(t).not_valid_after(t + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def test_an_expired_document_signer_is_refused_before_the_queue(client, chain):
    expired = _expired_cert()
    asked = len(chain["priority"])
    for i in range(5):
        r = _post(client, body(7500 + i, der=expired), "100.64.0.5")
        assert r.status_code == 400 and "expired" in r.json()["message"]
    assert len(chain["priority"]) == asked, "no gas-check"
    assert not ratelimit.client_refused_out(ratelimit.refusal_key("100.64.0.5"))


def test_dsc_expiry_leaves_the_edges_to_the_chain():
    der = base64.b64decode(_expired_cert())
    after = x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp()
    assert not gas._dsc_expired(der, now=after + gas._DATE_SLACK_SECONDS - 1)
    assert gas._dsc_expired(der, now=after + gas._DATE_SLACK_SECONDS + 1)
    assert not gas._dsc_expired(b"not a certificate")


def test_refusals_are_keyed_per_64_and_requests_per_48():
    a, b = "2001:db8:1:0::1", "2001:db8:1:1::1"
    assert ratelimit.client_key(a) == ratelimit.client_key(b)
    assert ratelimit.refusal_key(a) != ratelimit.refusal_key(b)
    assert ratelimit.refusal_key("2001:db8:1:0::1") == ratelimit.refusal_key("2001:db8:1:0:ffff::2")
    assert ratelimit.refusal_key("::ffff:100.64.0.1") == ratelimit.refusal_key("100.64.0.1") == \
        ratelimit.client_key("100.64.0.1")


# --- L1: a stamp is consumed before the lane's await ---------------------------

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
    assert _post(client, req, "198.51.100.60").status_code == 200
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
        assert _post(client, req, "198.51.100.61").status_code == 200
        assert chain["priority"][-1] is False
    finally:
        ratelimit.release_signer_lane(dsc)
    s = req["pow"]
    pow.check(s["ts"], s["nonce"], req["public_signals"][config.PASSPORT_ADDRESS_INDEX],
              req["public_signals"][config.PASSPORT_NULLIFIER_INDEX])  # not Rejected


# --- I2: decimal public signals are cut from logged errors ----------------------

def test_coarse_cuts_decimal_signals():
    nf = "20721221850428050168833700122818390286788073887706614806955557958870761234"
    out = gas._coarse(f"nullifier {nf} refused; 1121 at height 52000")
    assert nf[:16] not in out and "<hex>" in out and "1121" in out and "52000" in out



# --- L2: staleness from the first pending handle event --------------------------

def test_handle_events_every_block_do_not_hide_a_stale_directory(tmp_path):
    """A handle event in every block kept `last - changed` under the
    threshold, so a snapshot whose refreshes kept failing never read
    stale. Now staleness counts from the first event it has not caught up
    with."""
    from services.privacy import handles as handles_mod
    from services.privacy.events import BlockDelta
    from services.privacy.store import Store, handles_stale

    store = Store(str(tmp_path / "i.db"))
    store.apply(BlockDelta(height=1, hash="h1", time=1000))
    store.replace_handles(1, 1000, [handles_mod.Entry("amy", "earth1x", "live", 10**9, 10**9 + 1)], None)
    n = 5
    for h in range(2, 2 + 3 * n):
        store.apply(BlockDelta(height=h, hash=f"h{h}", time=1000 + h, handles_changed=True))
    assert store.meta("handles_pending_height") == "2"
    assert handles_stale(store.conn, n), "behind since height 2, not since the latest event"
    assert not handles_stale(store.conn, 3 * n + 1)
    # A snapshot at the last height catches up and clears it.
    last = 1 + 3 * n
    store.replace_handles(last, 2000, [], None)
    assert store.meta("handles_pending_height") is None
    assert not handles_stale(store.conn, 1)
    # The next event starts a new pending height.
    store.apply(BlockDelta(height=last + 1, hash="x", time=3000, handles_changed=True))
    assert store.meta("handles_pending_height") == str(last + 1)
    store.close()


def test_an_index_without_a_pending_height_falls_back_to_the_latest_event(tmp_path):
    from services.privacy.store import Store, handles_stale

    store = Store(str(tmp_path / "i.db"))
    for k, v in (("handles_height", "5"), ("handles_changed_height", "6"), ("last_height", "10")):
        store.set_meta(k, v)
    assert not handles_stale(store.conn, 5)
    assert handles_stale(store.conn, 4)
    store.close()
