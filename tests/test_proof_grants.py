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
# A real P-256 DSC certificate (tests/fixtures/dsc) and its chain commitment
# (pinned against x/pki/certs.DscCommitmentOf in test_audit4): reg_body's
# dsc_der and public_signals[3] agree, as a real registration's do.
_DSC_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dsc")
DSC_DER = open(os.path.join(_DSC_DIR, "dsc_p256.der"), "rb").read()
DSC_DER_B64 = base64.b64encode(DSC_DER).decode()
DSC_KEY = int("304606d727af8b6715f57c615779a33f1b00c00a1c5f50b7dd704b57a62ace59", 16)
NF = int("aa" * 32, 16) % P
NF_HEX = privacy.field_bytes(NF).hex()
OTHER_ADDRESS = "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"


def field_b64(v: int) -> str:
    return base64.b64encode(v.to_bytes(32, "big")).decode()


def today_yymmdd(offset_days: int = 0) -> int:
    t = time.gmtime(time.time() + offset_days * 86400)
    return (t.tm_year % 100) * 10000 + t.tm_mon * 100 + t.tm_mday


PC_GAS = (0x1234).to_bytes(32, "big")
# Amount-blind v2 ciphertexts: exactly 177 bytes each.
CT_ANML, CT_ERTH, CT_GAS = bytes([1]) * 177, bytes([2]) * 177, bytes([3]) * 177


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def signals(nf: int = NF, date: int | None = None, idc=11, pc_anml=12, pc_erth=13, affiliate: str = "",
            ct_anml: bytes = CT_ANML, ct_erth: bytes = CT_ERTH) -> list[str]:
    """[current_date, binding, nullifier, dsc_key], the earth-1 lean_poa layout."""
    aff = 0
    _, data = bech32.bech32_decode(affiliate) if affiliate else (None, None)
    if data is not None:
        aff = privacy.bytes_field(bytes(bech32.convertbits(data, 5, 8, False)))
    binding = privacy.registration_binding(idc, pc_anml, ct_anml, pc_erth, ct_erth, aff)
    return [str(today_yymmdd() if date is None else date), str(binding), str(nf), str(DSC_KEY)]


def reg_body(gas_pc: bytes = PC_GAS, nf: int = NF, **over):
    body = {"proof": B64, "public_signals": signals(nf, affiliate=over.get("affiliate", "")),
            "signature_algorithm": "lean_poa", "dsc_der": DSC_DER_B64,
            "idc": field_b64(11), "pc_anml": field_b64(12), "pc_erth": field_b64(13),
            "ciphertext_anml": b64(CT_ANML), "ciphertext_erth": b64(CT_ERTH),
            "pc_gas": base64.b64encode(gas_pc).decode(), "ciphertext_gas": b64(CT_GAS)}
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

    async def registration(msg, priority=False):
        state.setdefault("priority", []).append(priority)
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
    assert shields == [(PC_GAS, CT_GAS)]
    asked = chain_says["asked"][0]
    assert "creator" not in asked and "pc_gas" not in asked
    assert asked["idc"] == field_b64(11) and asked["pc_erth"] == field_b64(13)
    assert asked["proof"] == B64
    assert (asked["ciphertext_anml"], asked["ciphertext_erth"]) == (b64(CT_ANML), b64(CT_ERTH))


def test_register_stores_only_the_passport_key(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    rows = sqlite3.connect(config.STATE_DB).execute("SELECT transaction_id, address FROM used_transactions").fetchall()
    assert len(rows) == 1
    grant_id, address = rows[0]
    assert grant_id == f"passport:{NF_HEX}:{time.strftime('%Y-%m-%d', time.gmtime())}"
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
    monkeypatch.setattr(config, "REGISTER_SWITCH_GRANT_MAX_PER_DAY", 0)
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    assert client.post("/gas/register", json=reg_body(nf=5)).status_code == 429
    assert len(chain_says["asked"]) == 1, "with both caps spent, checked before gas-check"
    # A switch cap left: the check runs, and a first registration is still refused.
    monkeypatch.setattr(config, "REGISTER_SWITCH_GRANT_MAX_PER_DAY", 1)
    assert client.post("/gas/register", json=reg_body(nf=6)).status_code == 429
    assert len(chain_says["asked"]) == 2


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
    {"ciphertext_gas": ""},  # required
    {"ciphertext_gas": b64(CT_GAS[:-1])},  # not exactly 177
    {"ciphertext_gas": b64(CT_GAS + b"\x00")},
    {"ciphertext_anml": ""},
    {"ciphertext_erth": b64(CT_ERTH[:-1])},
    {"affiliate": "cosmos1abc"},
    {"affiliate": OTHER_ADDRESS.upper()},  # not the canonical (lowercase) encoding
])
def test_register_rejects_malformed_fields_before_asking(client, shields, chain_says, over):
    assert client.post("/gas/register", json=reg_body(**over)).status_code == 400
    assert chain_says["asked"] == []


def test_failed_shield_gives_the_passport_back(client, chain_says, monkeypatch):
    async def boom(pc, ct):
        raise RuntimeError("insufficient funds")

    monkeypatch.setattr(chain, "shield_dust", boom)
    assert client.post("/gas/register", json=reg_body()).status_code == 502
    assert replay.peek(f"passport:{NF_HEX}:{time.strftime('%Y-%m-%d', time.gmtime())}") is False
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


def test_logs_never_tie_the_passport_to_the_gas_tx(client, chain_says, monkeypatch, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    tx_hash = "AB" * 32

    async def ok(pc, ct):
        return tx_hash
    monkeypatch.setattr(chain, "shield_dust", ok)
    assert client.post("/gas/register", json=reg_body()).status_code == 200

    async def failed(pc, ct):
        raise RuntimeError(f"tx {tx_hash} failed: insufficient funds")
    monkeypatch.setattr(chain, "shield_dust", failed)
    assert client.post("/gas/register", json=reg_body(nf=77)).status_code == 502

    chain_says["registration"] = {"ok": False, "error": f"nullifier {NF_HEX} already registered"}
    assert client.post("/gas/register", json=reg_body(nf=78)).status_code == 403
    for text in (tx_hash, tx_hash.lower(), NF_HEX, PC_GAS.hex()):
        assert text not in caplog.text
    assert "registration gas note sent" in caplog.text


def test_unresolved_without_a_tx_hash_gives_the_passport_back(client, chain_says, monkeypatch):
    async def unresolved(pc, ct):
        raise chain.SendUnresolved("", TimeoutError())

    monkeypatch.setattr(chain, "shield_dust", unresolved)
    assert client.post("/gas/register", json=reg_body()).status_code == 502
    assert not replay.peek(f"passport:{NF_HEX}:{time.strftime('%Y-%m-%d', time.gmtime())}")


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
    assert replay.peek(f"passport:{(12345).to_bytes(32, 'big').hex()}:{time.strftime('%Y-%m-%d', time.gmtime())}")


def test_a_nullifier_gas_check_disagrees_with_is_503_and_unclaimed(client, shields, chain_says):
    chain_says["registration"] = {"ok": True, "nullifier": "bb" * 32, "switched": False}
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert shields == []
    assert not replay.peek(f"passport:{NF_HEX}:{time.strftime('%Y-%m-%d', time.gmtime())}")


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
    # same notes, other ciphertexts: the binding covers Bytes(ct_anml), Bytes(ct_erth)
    {"ciphertext_anml": b64(bytes([9]) * 177)},
    {"ciphertext_erth": b64(CT_ANML)},
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
    ratelimit._busy.add(ratelimit.client_key("203.0.113.9"))  # a check of this client's is in flight
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


@pytest.mark.parametrize("field", ["ciphertext_anml", "ciphertext_erth", "ciphertext_gas"])
def test_every_ciphertext_is_required(client, shields, chain_says, field):
    body = reg_body()
    del body[field]
    assert client.post("/gas/register", json=body).status_code == 422
    assert chain_says["asked"] == []


def test_shield_dust_refuses_a_ciphertext_the_chain_would():
    import asyncio
    with pytest.raises(ValueError):
        asyncio.run(chain.shield_dust(PC_GAS, b"x" * 176))


# --- audit 3: once per passport in any 30 days -----------------------------------

def _granted(grant_id: str, days_ago: float):
    replay._db().execute("INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, '', ?)",
                         (grant_id, int(time.time() - days_ago * 86400)))
    replay._db().commit()


def test_a_month_rollover_is_not_a_second_grant(client, shields, chain_says):
    """Keyed by calendar month, a grant on the 31st and one on the 1st were two
    grants a day apart. An id in the old :YYYY-MM form counts too."""
    _granted(f"passport:{NF_HEX}:2026-09", days_ago=1)
    assert client.post("/gas/register", json=reg_body()).status_code == 409
    assert shields == [] and chain_says["asked"] == []
    # Another passport is unaffected.
    assert client.post("/gas/register", json=reg_body(nf=5)).status_code == 200


def test_a_passport_is_granted_again_after_30_days(client, shields, chain_says):
    _granted(f"passport:{NF_HEX}:2026-08-01", days_ago=31)
    assert client.post("/gas/register", json=reg_body()).status_code == 200


def test_the_30_day_window_is_decided_atomically_in_claim():
    _granted(f"passport:{NF_HEX}:2026-09-30", days_ago=2)
    assert not replay.claim(f"passport:{NF_HEX}:2026-10-02", prefix="passport:", max_per_day=10,
                            key_prefix=f"passport:{NF_HEX}:", once_per=30 * 86400)
