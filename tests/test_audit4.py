"""Audit round 4 (backend): regressions for each finding.

B5: _yymmdd_unix took Feb 31 as Mar 3 (Go's time.Date normalisation); the
chain's yymmddToUnix now refuses a date that does not round-trip, so must we.
"""
import pytest

from routers import gas


@pytest.mark.parametrize("v", [250231, 250230, 250431, 230229, 251131])
def test_impossible_dates_are_refused_like_the_chain(v):
    with pytest.raises(ValueError, match="calendar date"):
        gas._yymmdd_unix(v)


def test_real_dates_still_parse():
    assert gas._yymmdd_unix(240229) == 1709164800  # 2024 is a leap year
    assert gas._yymmdd_unix(250101) == 1735689600
    assert gas._yymmdd_unix(251231) == 1767139200


# --- B2: a non-200 answer after the node took the tx -------------------------
#
# poc test_poc_nonok_http_double_grant.py: cosmpy's REST client raises a bare
# RuntimeError for any non-200 answer. Behind Cloudflare a 524 can arrive
# after the node accepted the tx; _broadcast took it for "moved nothing",
# _grant_note released the passport and the retry was paid again.

from cosmpy.aerial.exceptions import BroadcastError  # noqa: E402

from services import chain as chain_mod  # noqa: E402
from tests.test_chain import SIGNED_HASH, _send_with  # noqa: E402
from tests.test_proof_grants import chain_says, reg_body  # noqa: E402,F401

CF_524 = RuntimeError("Error when sending a POST request.\n Request: {...}\n Response: 524, b'error code: 524'")


def test_a_non_200_after_accept_is_resolved_by_hash(monkeypatch):
    assert _send_with(monkeypatch, CF_524, landed=True) == SIGNED_HASH


def test_a_non_200_never_seen_is_unresolved(monkeypatch):
    with pytest.raises(chain_mod.SendUnresolved) as info:
        _send_with(monkeypatch, CF_524)
    assert info.value.tx_hash == SIGNED_HASH


def test_checktx_refusal_moved_nothing(monkeypatch):
    with pytest.raises(BroadcastError):
        _send_with(monkeypatch, BroadcastError("H", "insufficient fees"))


def test_already_in_mempool_is_resolved_by_hash(monkeypatch):
    exc = BroadcastError("H", "tx already exists in cache")
    assert _send_with(monkeypatch, exc, landed=True) == SIGNED_HASH


def _cf524_broadcast(monkeypatch, landed_after_first: bool):
    """chain internals stubbed: the first broadcast raises a 524 after the tx
    reached the mempool (it lands); later ones succeed."""
    import asyncio

    from routers import gas

    sent = []

    class Tx:
        tx = type("T", (), {"SerializeToString": lambda self: b"signed%d" % len(sent)})()

    class Client:
        def broadcast_tx(self, tx):
            sent.append(tx)
            if len(sent) == 1:
                raise CF_524
            return chain_mod.SubmittedTx(self, chain_mod.tx_hash_of(tx))

    def waited(self, *a, **k):
        if not landed_after_first:
            raise chain_mod.QueryTimeoutError()
        return self

    class _W:
        def address(self):
            return "earth1x"

    monkeypatch.setattr(chain_mod, "Transaction", lambda: type("B", (), {"add_message": lambda self, m: None, "tx": Tx.tx})())
    monkeypatch.setattr(chain_mod, "prepare_basic_transaction", lambda *a, **k: None)
    monkeypatch.setattr(chain_mod.shielded_msg, "build", lambda *a, **k: None)
    monkeypatch.setattr(chain_mod.SubmittedTx, "wait_to_complete", waited)
    monkeypatch.setattr(chain_mod, "_client", Client())
    monkeypatch.setattr(chain_mod, "_wallet", _W())
    monkeypatch.setattr(chain_mod, "_send_lock", asyncio.Lock())
    assert gas.chain is chain_mod
    return sent


def test_the_passport_is_paid_once(client, chain_says, monkeypatch):
    sent = _cf524_broadcast(monkeypatch, landed_after_first=True)
    r1 = client.post("/gas/register", json=reg_body())
    assert r1.status_code == 200, r1.text
    r2 = client.post("/gas/register", json=reg_body())
    assert r2.status_code == 409
    assert len(sent) == 1


def test_an_unseen_524_keeps_the_passport_claimed(client, chain_says, monkeypatch):
    sent = _cf524_broadcast(monkeypatch, landed_after_first=False)
    r1 = client.post("/gas/register", json=reg_body())
    assert r1.status_code == 202 and r1.json()["tx_hash"]
    assert client.post("/gas/register", json=reg_body()).status_code == 409
    assert len(sent) == 1


# --- B1: the reserved lane ---------------------------------------------------
#
# poc test_poc_reserved_lane_uncounted.py: junk copying a known DSC
# commitment into public_signals[3] got the reserved lane with only a
# POW_RESERVED_BITS stamp, and since gas-check refused it before proof
# verification (dsc_der does not chain, is not the named DSC, the affiliate
# handle is not live) the refusal was never counted: no cooldown, no shedding.

import os  # noqa: E402

import config  # noqa: E402
from services import dsccommit, knowndsc, ratelimit  # noqa: E402
from services.zk import privacy  # noqa: E402
from tests.test_proof_grants import DSC_DER_B64, DSC_KEY  # noqa: E402
from tests.test_queue import with_pow  # noqa: E402
from tests.test_register_dos import DE, body, chain, post  # noqa: E402,F401

CHEAP_REFUSALS = [
    "no trusted issuing CSCA found",
    "proof is not bound to the supplied DSC: proof public inputs do not match",
    'affiliate_handle "amy": affiliate_handle is not a live handle',
    "invalid certificate",
]

_DSC = os.path.join(os.path.dirname(__file__), "fixtures", "dsc")


# x/pki/certs.DscCommitmentOf over each certificate, from the chain's own code
# (csca_*: x/pki/certs/testdata; dsc_*: generated here). Brainpool and the
# explicit-parameter P-521 are what `cryptography` cannot load.
@pytest.mark.parametrize("name,want", [
    ("csca_brainpoolP256r1.der", "268948bb8e64736bdc99290b15d54e82cc588b2cf5d4fe89c7aa2f4c70d51a56"),
    ("csca_brainpoolP512r1.der", "09832cfbab77ee97dbfabee18ea29b8bf65854c92bc94b9f17f62bed01bbfcae"),
    ("csca_p521_explicit.der", "2f266d7247853a1d5b98df816ed33aa115d36a7cf087a6093b036ce2fb7c85a1"),
    ("csca_rsa.der", "09152b8589dabb5428ae48775a3fb60bbe46f597d01a635cb4298b2ba47b6929"),
    ("dsc_p256.der", "304606d727af8b6715f57c615779a33f1b00c00a1c5f50b7dd704b57a62ace59"),
    ("dsc_p384.der", "25f951db441d4b3dec429c70838a5d682a20426fb81f7e03df5aed44b1332584"),
    ("dsc_rsa2048.der", "2ba8a977d31f882307f980ec68766aaca880f9e0249e8bd8543b8fe8e19bd7bf"),
])
def test_dsc_commitment_matches_the_chain(name, want):
    with open(os.path.join(_DSC, name), "rb") as f:
        assert dsccommit.commitment(f.read()).hex() == want


def test_dsc_commitment_matches_the_circuit():
    """zk/ultrahonk/testdata/lean_poa: dsc_pubkey -> expected_dsc_key (P-256, tag 1)."""
    key = bytes.fromhex("75c72e3b24013b813e7ee78da1fcf7cd1ac902030ea119b86df9822eddcaac49"
                        "a8a3b10d8765588476ed35eb6141681534bb7164a2fa9d6c7dd82140776c471d")
    assert int.from_bytes(dsccommit.commitment_of_key(dsccommit.TAG_P256, key), "big") == \
        17137993880610033746992863696376072247659308979702652622358731864446692122039


@pytest.mark.parametrize("der", [b"", b"AAAA", b"\x30\x03\x02\x01\x01", b"\x30\x84\xff\xff\xff\xff"])
def test_junk_has_no_commitment(der):
    assert dsccommit.commitment(der) is None


def test_curve_constants_match_ecdsa():
    import ecdsa

    for c, oid in [(ecdsa.NIST256p, "1.2.840.10045.3.1.7"), (ecdsa.NIST384p, "1.3.132.0.34"),
                   (ecdsa.NIST521p, "1.3.132.0.35"), (ecdsa.BRAINPOOLP256r1, "1.3.36.3.3.2.8.1.1.7"),
                   (ecdsa.BRAINPOOLP384r1, "1.3.36.3.3.2.8.1.1.11"), (ecdsa.BRAINPOOLP512r1, "1.3.36.3.3.2.8.1.1.13")]:
        _, p, n = dsccommit._CURVES[oid]
        assert (p, n) == (c.curve.p(), c.order), c.name


def test_a_copied_commitment_without_its_certificate_gets_no_priority(client, chain, monkeypatch):
    """The PoC's flood: a known commitment beside junk (or another signer's) dsc_der."""
    monkeypatch.setattr(config, "REGISTER_DSC_FAILURES_BEFORE_COOLDOWN", 5)
    knowndsc.set_known({privacy.field_bytes(DSC_KEY)})
    for i, der in enumerate(["AAAA", DE]):
        r = post(client, with_pow(body(70000 + i, der=der), config.POW_RESERVED_BITS))
        assert r.status_code == 200
        assert chain["priority"][-1] is False, "dsc_der is not the signer public_signals names"
    assert post(client, with_pow(body(70010, der=DSC_DER_B64), config.POW_RESERVED_BITS)).status_code == 200
    assert chain["priority"][-1] is True


def test_every_refusal_in_the_reserved_lane_counts(client, chain, monkeypatch):
    """The PoC's flood with the real certificate: cheap refusals now demote the signer."""
    monkeypatch.setattr(config, "REGISTER_DSC_FAILURES_BEFORE_COOLDOWN", 5)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 30)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_MINUTE", 3)
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    held = 0
    for i in range(20):
        nf = 71000 + i
        chain["refuse"][nf] = CHEAP_REFUSALS[i % len(CHEAP_REFUSALS)]
        r = post(client, with_pow(body(nf), config.POW_RESERVED_BITS))
        assert r.status_code == 403, r.text
        held += chain["priority"][-1]
    assert held == 5, "the lane is lost after REGISTER_DSC_FAILURES_BEFORE_COOLDOWN refusals"
    assert ratelimit.dsc_cooling(dsc)
    # Counted against the signer only: the network budget (3) is untouched.
    assert ratelimit.shedding(None, None) is None


def test_reserved_lane_refusals_spend_the_signers_budget(client, chain, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_DSC_FAILURES_BEFORE_COOLDOWN", 0)
    monkeypatch.setattr(config, "REGISTER_REFUSALS_PER_DSC_PER_MINUTE", 3)
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    for i in range(3):
        chain["refuse"][72000 + i] = CHEAP_REFUSALS[2]
        assert post(client, with_pow(body(72000 + i), config.POW_RESERVED_BITS)).status_code == 403
    assert ratelimit.shedding(dsc, None) == "signer"


def test_ordinary_lane_cheap_refusals_still_count_nothing(client, chain):
    dsc = privacy.field_bytes(DSC_KEY)
    knowndsc.set_known({dsc})
    for i in range(10):
        chain["refuse"][73000 + i] = CHEAP_REFUSALS[i % len(CHEAP_REFUSALS)]
        assert post(client, body(73000 + i)).status_code == 403  # no work: ordinary lane
    assert not ratelimit.dsc_cooling(dsc) and ratelimit.shedding(dsc, None) is None


# --- B3: /privacy page cost ---------------------------------------------------
#
# poc_privacy_page_cost.py: an uncached 5000-row /notes page cost ~8 MiB of
# heap and ~0.3 s here (seconds on the 0.1-CPU lease), and every distinct
# from_pos was a distinct CDN key, so the cache was bypassed at will. Now:
# fixed page sizes, aligned cursors, an in-flight cap and a per-client rate.

import asyncio  # noqa: E402
import tracemalloc  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from routers import privacy as privacy_router  # noqa: E402
from services.privacy import store as store_mod  # noqa: E402
from services.privacygate import PrivacyGate  # noqa: E402

BASE = "/privacy/earth-1/" + "ab" * 8


@pytest.fixture
def notes_index(tmp_path, monkeypatch):
    db = str(tmp_path / "idx.db")
    monkeypatch.setattr(config, "INDEX_DB", db)
    c = store_mod.connect(db)
    c.execute("BEGIN")
    c.executemany("INSERT INTO meta VALUES (?,?)",
                  [("chain_id", "earth-1"), ("genesis_hash", "ab" * 32), ("last_height", "10")])
    c.execute("INSERT INTO blocks VALUES (1,'x',0)")
    c.executemany("INSERT INTO notes VALUES (?,?,?,?,?)",
                  ((i, os.urandom(32), os.urandom(177), 1, None) for i in range(5500)))
    c.execute("COMMIT")
    c.close()
    app = FastAPI()
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(PrivacyGate)
    app.include_router(privacy_router.router)
    return TestClient(app)


def test_only_aligned_pages_of_fixed_sizes(notes_index):
    get = notes_index.get
    for params in ({"from_pos": 1}, {"from_pos": 999}, {"from_pos": 100, "limit": 1000},
                   {"from_pos": 0, "limit": 5000}, {"from_pos": 0, "limit": 999}):
        r = get(BASE + "/notes", params=params)
        assert r.status_code == 400, params
        assert r.headers["cache-control"] == "no-store"
    r = get(BASE + "/notes", params={"from_pos": 1000})
    body = r.json()
    assert [n[0] for n in body["notes"]] == list(range(1000, 2000))
    assert body["complete"] and body["next_pos"] == 2000 and "immutable" in r.headers["cache-control"]
    tip = get(BASE + "/notes", params={"from_pos": 5000}).json()
    assert [n[0] for n in tip["notes"]] == list(range(5000, 5500)) and not tip["complete"]
    assert tip["next_pos"] == 5500, "where the data ends; the wallet asks for page 5000 again later"
    r = get(BASE + "/notes", params={"from_pos": 200, "limit": 100})
    assert [n[0] for n in r.json()["notes"]] == list(range(200, 300))


def test_a_max_page_is_bounded(notes_index):
    tracemalloc.start()
    r = notes_index.get(BASE + "/notes", params={"from_pos": 0, "limit": config.PRIVACY_PAGE_MAX},
                        headers={"accept-encoding": "gzip"})
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r.status_code == 200 and len(r.json()["notes"]) == 1000
    assert peak < 4 * 2**20, f"peak heap {peak / 2**20:.1f} MiB for one max page"


def test_privacy_rate_limit_per_client(notes_index, monkeypatch):
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    monkeypatch.setattr(config, "PRIVACY_IP_MAX_PER_WINDOW", 3)
    a, b = {"cf-connecting-ip": "203.0.113.1"}, {"cf-connecting-ip": "203.0.113.2"}
    for _ in range(3):
        assert notes_index.get("/privacy/status", headers=a).status_code == 200
    r = notes_index.get(BASE + "/notes", headers=a)
    assert r.status_code == 429 and r.headers["cache-control"] == "no-store" and r.headers["retry-after"]
    assert notes_index.get("/privacy/status", headers=b).status_code == 200, "another client is not limited"


def test_privacy_in_flight_cap():
    """Past PRIVACY_MAX_CONCURRENT the gate answers 503 at once; other paths pass."""
    release = asyncio.Event()
    entered = []

    async def slow_app(scope, receive, send):
        entered.append(scope["path"])
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    gate = PrivacyGate(slow_app)

    async def call(path):
        sent = []

        async def send(m):
            sent.append(m)

        async def receive():
            return {"type": "http.request", "body": b""}

        await gate({"type": "http", "path": path, "headers": [], "client": ("198.51.100.9", 1)}, receive, send)
        return sent[0]["status"]

    async def go():
        slots = [asyncio.create_task(call(BASE + "/notes")) for _ in range(config.PRIVACY_MAX_CONCURRENT)]
        await asyncio.sleep(0.01)
        refused = await call(BASE + "/notes")
        other = asyncio.create_task(call("/gas/pow"))
        await asyncio.sleep(0.01)
        release.set()
        return refused, await asyncio.gather(*slots), await other

    refused, ok, other = asyncio.run(go())
    assert refused == 503 and ok == [200] * config.PRIVACY_MAX_CONCURRENT and other == 200
    assert gate.in_flight == 0


# --- B4: switch grants are capped apart ----------------------------------------

from services import replay  # noqa: E402


def _verdict(switched):
    async def registration(msg, priority=False):
        nf = int(msg["public_signals"][2])
        return {"ok": True, "nullifier": privacy.field_bytes(nf).hex(), "switched": switched}
    return registration


def test_switch_grants_do_not_spend_the_new_registrant_cap(client, monkeypatch):
    from routers import gas
    from services import gascheck

    async def shield(pc, ct):
        return "H"
    monkeypatch.setattr(gas.chain, "shield_dust", shield)
    monkeypatch.setattr(config, "REGISTER_GRANT_MAX_PER_DAY", 2)
    monkeypatch.setattr(config, "REGISTER_SWITCH_GRANT_MAX_PER_DAY", 3)
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 100)

    monkeypatch.setattr(gascheck, "registration", _verdict(True))
    codes = [client.post("/gas/register", json=body(80000 + i)).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429], "switches stop at their own cap"

    monkeypatch.setattr(gascheck, "registration", _verdict(False))
    codes = [client.post("/gas/register", json=body(81000 + i)).status_code for i in range(3)]
    assert codes == [200, 200, 429], "first registrations still have their whole cap"
    assert replay.limit_reached("passport:", 2) and replay.limit_reached("passport:", 3, kind="switch")


def test_both_caps_spent_refuses_before_the_check(client, monkeypatch):
    from services import gascheck

    asked = []

    async def registration(msg, priority=False):
        asked.append(msg)
        return {"ok": True}
    monkeypatch.setattr(gascheck, "registration", registration)
    monkeypatch.setattr(config, "REGISTER_GRANT_MAX_PER_DAY", 0)
    monkeypatch.setattr(config, "REGISTER_SWITCH_GRANT_MAX_PER_DAY", 0)
    assert client.post("/gas/register", json=body(82000)).status_code == 429
    assert asked == []
