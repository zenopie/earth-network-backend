"""The registration grant: /gas/register funds a shielded fee note.

The chain's verdict is stood in for here; what is under test is what the
backend does around it — the cheap checks that refuse before gas-check runs
(replay, binding, date, bounds, per-client limits, daily cap), the key it
grants under, what it keeps, and telling a refusal apart from a check that
could not be made.
test_gascheck_live runs the real command against a chain when EARTHD_BIN and
GAS_CHECK_LIVE_MSG point at one.
"""
import base64
import json
import os
import sqlite3
import time

import bech32
import pytest

import config
from services import chain, gascheck, ratelimit, replay
from services.zk import privacy
from services.zk.poseidon2 import P

B64 = base64.b64encode(b"x").decode()
NF = int("aa" * 32, 16) % P
NF_HEX = privacy.field_bytes(NF).hex()
OTHER_ADDRESS = "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"


def field_b64(v: int) -> str:
    return base64.b64encode(v.to_bytes(32, "big")).decode()


def today_yymmdd(offset_days: int = 0) -> int:
    t = time.gmtime(time.time() + offset_days * 86400)
    return (t.tm_year % 100) * 10000 + t.tm_mon * 100 + t.tm_mday


PC_GAS = (0x1234).to_bytes(32, "big")


def signals(nf: int = NF, date: int | None = None, idc=11, pc_anml=12, pc_erth=13, affiliate: str = "") -> list[str]:
    """[current_date, binding, nullifier, dsc_key], the earth-1 lean_poa layout."""
    aff = 0
    _, data = bech32.bech32_decode(affiliate) if affiliate else (None, None)
    if data is not None:
        aff = privacy.bytes_field(bytes(bech32.convertbits(data, 5, 8, False)))
    binding = privacy.registration_binding(idc, pc_anml, pc_erth, aff)
    return [str(today_yymmdd() if date is None else date), str(binding), str(nf), "7"]


def reg_body(gas_pc: bytes = PC_GAS, nf: int = NF, **over):
    body = {"proof": B64, "public_signals": signals(nf, affiliate=over.get("affiliate", "")),
            "signature_algorithm": "lean_poa", "dsc_der": B64,
            "idc": field_b64(11), "pc_anml": field_b64(12), "pc_erth": field_b64(13),
            "ciphertext_anml": B64, "ciphertext_erth": "",
            "pc_gas": base64.b64encode(gas_pc).decode(), "ciphertext_gas": B64}
    body.update(over)
    return body


@pytest.fixture
def shields(monkeypatch):
    """Records every (pc, ciphertext) a gas note is shielded to, in place of the chain."""
    sent: list[tuple[bytes, bytes]] = []

    async def fake_shield(pc: bytes, ciphertext: bytes) -> str:
        sent.append((pc, ciphertext))
        return f"HASH{len(sent)}"

    monkeypatch.setattr(chain, "shield_dust", fake_shield)
    return sent


@pytest.fixture
def chain_says(monkeypatch):
    """Sets the verdict gas-check returns; records the MsgRegister it was asked about."""
    state = {"registration": None, "asked": []}

    async def registration(msg):
        state["asked"].append(msg)
        v = state["registration"]
        if isinstance(v, Exception):
            raise v
        if v is None:  # the chain accepts, for the nullifier at index 2
            return {"ok": True, "nullifier": privacy.field_bytes(int(msg["public_signals"][2])).hex(), "switched": False}
        return v

    monkeypatch.setattr(gascheck, "registration", registration)
    return state


def test_register_grant_shields_to_pc_gas(client, shields, chain_says):
    resp = client.post("/gas/register", json=reg_body())
    assert resp.status_code == 200, resp.text
    assert resp.json()["tx_hash"] == "HASH1"
    assert shields == [(PC_GAS, b"x")]
    asked = chain_says["asked"][0]
    assert "creator" not in asked and "pc_gas" not in asked
    assert asked["idc"] == field_b64(11) and asked["pc_erth"] == field_b64(13)
    assert asked["proof"] == B64


def test_register_stores_only_the_passport_key(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    rows = sqlite3.connect(config.STATE_DB).execute("SELECT transaction_id, address FROM used_transactions").fetchall()
    assert len(rows) == 1
    grant_id, address = rows[0]
    assert grant_id == f"passport:{NF_HEX}:{time.strftime('%Y-%m', time.gmtime())}"
    assert address == ""
    assert PC_GAS.hex() not in grant_id


def test_register_is_once_per_passport_whatever_the_note(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    # Same passport (nullifier), another pc: no second grant this month.
    assert client.post("/gas/register", json=reg_body((0x99).to_bytes(32, "big"))).status_code == 409
    assert len(shields) == 1


def test_different_passports_each_get_a_grant(client, shields, chain_says):
    for i in range(3):
        assert client.post("/gas/register", json=reg_body(nf=i + 1)).status_code == 200
    assert len(shields) == 3


def test_daily_cap_applies(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_GRANT_MAX_PER_DAY", 1)
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    assert client.post("/gas/register", json=reg_body(nf=5)).status_code == 429
    assert len(chain_says["asked"]) == 1, "the cap is checked before gas-check"


def test_register_refusal_carries_the_chains_reason(client, shields, chain_says):
    chain_says["registration"] = {"ok": False, "error": "passport expired"}
    resp = client.post("/gas/register", json=reg_body())
    assert resp.status_code == 403
    assert "passport expired" in resp.json()["message"]
    assert shields == []


def test_register_unavailable_is_503_not_a_refusal(client, shields, chain_says):
    chain_says["registration"] = gascheck.Unavailable("node down")
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert shields == []


@pytest.mark.parametrize("over", [
    {"proof": "not base64!"},
    {"pc_gas": base64.b64encode(b"\x01" * 31).decode()},
    {"pc_gas": base64.b64encode(P.to_bytes(32, "big")).decode()},  # not canonical
    {"idc": B64},
    {"ciphertext_gas": base64.b64encode(b"\x00" * 1025).decode()},
    {"affiliate": "cosmos1abc"},
])
def test_register_rejects_malformed_fields_before_asking(client, shields, chain_says, over):
    assert client.post("/gas/register", json=reg_body(**over)).status_code == 400
    assert chain_says["asked"] == []


def test_failed_shield_gives_the_passport_back(client, chain_says, monkeypatch):
    async def boom(pc, ct):
        raise RuntimeError("insufficient funds")

    monkeypatch.setattr(chain, "shield_dust", boom)
    assert client.post("/gas/register", json=reg_body()).status_code == 502
    assert replay.peek(f"passport:{NF_HEX}:{time.strftime('%Y-%m', time.gmtime())}") is False
    sent = []

    async def ok(pc, ct):
        sent.append(pc)
        return "H"

    monkeypatch.setattr(chain, "shield_dust", ok)
    assert client.post("/gas/register", json=reg_body()).status_code == 200


def test_unresolved_shield_keeps_the_passport(client, chain_says, monkeypatch):
    async def unresolved(pc, ct):
        raise chain.SendUnresolved("ABC", TimeoutError())

    monkeypatch.setattr(chain, "shield_dust", unresolved)
    resp = client.post("/gas/register", json=reg_body())
    assert resp.status_code == 202 and resp.json()["tx_hash"] == "ABC"
    assert client.post("/gas/register", json=reg_body()).status_code == 409


@pytest.mark.parametrize("path", ["/gas/human", "/gas/transparent", "/gas/challenge", "/gas/ios", "/gas/android"])
def test_only_register_is_left(client, path):
    assert client.post(path, json={"address": "earth1x"}).status_code == 404


def test_removed_services_are_gone():
    import importlib.util

    for name in ("services.appattest", "services.keyattest", "services.challenges"):
        assert importlib.util.find_spec(name) is None
    assert not hasattr(gascheck, "human") and not hasattr(gascheck, "membership")
    assert not hasattr(chain, "send_dust")
    for name in ("IOS_APP_ID", "APP_ATTEST_ALLOW_DEVELOPMENT", "ANDROID_SIGNING_CERT_SHA256",
                 "CHALLENGE_TTL_SECONDS", "GRANT_MAX_PER_ADDRESS_PER_DAY", "GRANT_MAX_PER_DAY"):
        assert not hasattr(config, name)


def test_gascheck_missing_binary_is_unavailable(monkeypatch):
    import asyncio

    monkeypatch.setattr(config, "EARTHD_BIN", "/nonexistent/earthd")
    with pytest.raises(gascheck.Unavailable):
        asyncio.run(gascheck.registration({}))


@pytest.mark.skipif(not (os.getenv("EARTHD_BIN") and os.getenv("GAS_CHECK_LIVE_MSG")),
                    reason="set EARTHD_BIN (a privacy-chain earthd) and GAS_CHECK_LIVE_MSG (a MsgRegister JSON file)")
def test_gascheck_live(monkeypatch, tmp_path):
    import asyncio

    monkeypatch.setattr(config, "EARTHD_BIN", os.environ["EARTHD_BIN"])
    monkeypatch.setattr(config, "EARTHD_HOME", str(tmp_path))
    msg = json.load(open(os.environ["GAS_CHECK_LIVE_MSG"]))
    verdict = asyncio.run(gascheck.registration(msg))
    assert "ok" in verdict


# --- cheap checks before gas-check -------------------------------------------

def test_replay_is_refused_before_gas_check(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    assert client.post("/gas/register", json=reg_body((0x99).to_bytes(32, "big"))).status_code == 409
    assert len(chain_says["asked"]) == 1, "a claimed passport never reaches gas-check"


def test_the_grant_is_keyed_on_public_signal_2(client, shields, chain_says):
    # earth-1 genesis personhood params: nullifier_index 2, address_index 1,
    # current_date_index 0. config mirrors them.
    assert (config.PASSPORT_NULLIFIER_INDEX, config.PASSPORT_ADDRESS_INDEX, config.PASSPORT_CURRENT_DATE_INDEX) == (2, 1, 0)
    assert client.post("/gas/register", json=reg_body(nf=12345)).status_code == 200
    assert replay.peek(f"passport:{(12345).to_bytes(32, 'big').hex()}:{time.strftime('%Y-%m', time.gmtime())}")


def test_a_nullifier_gas_check_disagrees_with_is_503_and_unclaimed(client, shields, chain_says):
    chain_says["registration"] = {"ok": True, "nullifier": "bb" * 32, "switched": False}
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert shields == []
    assert not replay.peek(f"passport:{NF_HEX}:{time.strftime('%Y-%m', time.gmtime())}")


def test_affiliate_is_part_of_the_binding(client, shields, chain_says):
    body = reg_body(affiliate=OTHER_ADDRESS)
    assert client.post("/gas/register", json=body).status_code == 200
    # The same proof with the affiliate dropped (or swapped) is bound to nothing here.
    body2 = reg_body(nf=2)
    body2["public_signals"] = signals(2, affiliate=OTHER_ADDRESS)
    assert client.post("/gas/register", json=body2).status_code == 400
    assert len(chain_says["asked"]) == 1


@pytest.mark.parametrize("over", [
    {"pc_erth": field_b64(99)},  # proof made for other notes
    {"idc": field_b64(99)},
])
def test_a_proof_bound_to_other_notes_is_refused_before_asking(client, shields, chain_says, over):
    resp = client.post("/gas/register", json=reg_body(**over))
    assert resp.status_code == 400 and "bound" in resp.json()["message"]
    assert chain_says["asked"] == []


@pytest.mark.parametrize("date", [today_yymmdd(-3), today_yymmdd(3), 261332, 260100, 1000000])
def test_a_stale_or_malformed_date_is_refused_before_asking(client, shields, chain_says, date):
    body = reg_body()
    body["public_signals"][0] = str(date)
    assert client.post("/gas/register", json=body).status_code == 400
    assert chain_says["asked"] == []


def test_yesterdays_date_is_within_the_skew(client, shields, chain_says):
    body = reg_body()
    body["public_signals"][0] = str(today_yymmdd(-1))
    assert client.post("/gas/register", json=body).status_code == 200


@pytest.mark.parametrize("sigs", [
    lambda s: s[:2],               # too few for nullifier_index 2
    lambda s: s + ["0"] * 13,      # 17 > 16
    lambda s: [],
    lambda s: s[:3] + ["0x07"],    # not decimal
    lambda s: s[:3] + ["+7"],
    lambda s: s[:3] + [str(P)],    # not canonical
])
def test_bad_public_signals_are_refused_before_asking(client, shields, chain_says, sigs):
    body = reg_body()
    body["public_signals"] = sigs(body["public_signals"])
    assert client.post("/gas/register", json=body).status_code == 400
    assert chain_says["asked"] == []


@pytest.mark.parametrize("over", [
    {"proof": ""},
    {"dsc_der": ""},
    {"dsc_der": base64.b64encode(b"\x00" * (8 * 1024 + 1)).decode()},
    {"ciphertext_anml": base64.b64encode(b"\x00" * 1025).decode()},
    {"signature_algorithm": ""},
])
def test_out_of_bounds_fields_are_refused_before_asking(client, shields, chain_says, over):
    assert client.post("/gas/register", json=reg_body(**over)).status_code == 400
    assert chain_says["asked"] == []


# --- per-client limits ---------------------------------------------------------

def test_per_ip_window_counts_junk_too(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 2)
    assert client.post("/gas/register", json=reg_body(proof="")).status_code == 400
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    resp = client.post("/gas/register", json=reg_body(nf=2))
    assert resp.status_code == 429
    assert len(chain_says["asked"]) == 1


def test_cf_connecting_ip_separates_clients(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 1)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    a, b = {"CF-Connecting-IP": "203.0.113.1"}, {"CF-Connecting-IP": "203.0.113.2"}
    assert client.post("/gas/register", json=reg_body(nf=1), headers=a).status_code == 200
    assert client.post("/gas/register", json=reg_body(nf=2), headers=a).status_code == 429
    assert client.post("/gas/register", json=reg_body(nf=3), headers=b).status_code == 200


def test_cf_connecting_ip_ignored_when_not_trusted(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_IP_MAX_PER_WINDOW", 1)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", False)
    assert client.post("/gas/register", json=reg_body(nf=1), headers={"CF-Connecting-IP": "203.0.113.1"}).status_code == 200
    # A new header value is not a new client: the peer is the same.
    assert client.post("/gas/register", json=reg_body(nf=2), headers={"CF-Connecting-IP": "203.0.113.2"}).status_code == 429


def test_one_gas_check_per_client_at_a_time(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    ratelimit._busy.add("203.0.113.9")  # a check of this client's is in flight
    resp = client.post("/gas/register", json=reg_body(), headers={"CF-Connecting-IP": "203.0.113.9"})
    assert resp.status_code == 429
    assert chain_says["asked"] == []
    assert client.post("/gas/register", json=reg_body(), headers={"CF-Connecting-IP": "203.0.113.10"}).status_code == 200


def test_the_client_slot_is_freed_after_the_check(client, shields, chain_says, monkeypatch):
    chain_says["registration"] = gascheck.Unavailable("node down")
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert ratelimit._busy == set()
    chain_says["registration"] = None
    assert client.post("/gas/register", json=reg_body()).status_code == 200


def test_the_window_slides():
    ratelimit.reset()
    lim = config.REGISTER_IP_MAX_PER_WINDOW
    for i in range(lim):
        assert ratelimit.allow("x", now=1000.0 + i)
    assert not ratelimit.allow("x", now=1000.0 + lim)
    assert ratelimit.allow("x", now=1000.0 + config.REGISTER_IP_WINDOW_SECONDS + 0.5)
