"""The registration grant: /gas/register funds a shielded fee note.

The chain's verdict is stood in for here; what is under test is what the
backend does with it — the limits, the key it grants under, what it keeps,
and telling a refusal apart from a check that could not be made.
test_gascheck_live runs the real command against a chain when EARTHD_BIN and
GAS_CHECK_LIVE_MSG point at one.
"""
import base64
import json
import os
import sqlite3
import time

import pytest

import config
from services import chain, gascheck, replay
from services.zk.poseidon2 import P

B64 = base64.b64encode(b"x").decode()


def field_b64(v: int) -> str:
    return base64.b64encode(v.to_bytes(32, "big")).decode()


PC_GAS = (0x1234).to_bytes(32, "big")


def reg_body(gas_pc: bytes = PC_GAS, **over):
    body = {"proof": B64, "public_signals": ["1", "2"], "signature_algorithm": "lean_poa", "dsc_der": B64,
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
    state = {"registration": {"ok": True, "nullifier": "aa" * 32, "switched": False}, "asked": []}

    async def registration(msg):
        state["asked"].append(msg)
        if isinstance(state["registration"], Exception):
            raise state["registration"]
        return state["registration"]

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
    assert grant_id.startswith("passport:" + "aa" * 32 + ":")
    assert address == ""
    assert PC_GAS.hex() not in grant_id


def test_register_is_once_per_passport_whatever_the_note(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    # Same passport (nullifier), another pc: no second grant this month.
    assert client.post("/gas/register", json=reg_body((0x99).to_bytes(32, "big"))).status_code == 409
    assert len(shields) == 1


def test_different_passports_each_get_a_grant(client, shields, chain_says):
    for i in range(3):
        chain_says["registration"] = {"ok": True, "nullifier": f"{i:064x}", "switched": False}
        assert client.post("/gas/register", json=reg_body()).status_code == 200
    assert len(shields) == 3


def test_daily_cap_applies(client, shields, chain_says, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_GRANT_MAX_PER_DAY", 1)
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    chain_says["registration"] = {"ok": True, "nullifier": "cc" * 32, "switched": False}
    assert client.post("/gas/register", json=reg_body()).status_code == 429


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
    assert replay.peek(f"passport:{'aa' * 32}:{time.strftime('%Y-%m', time.gmtime())}") is False
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
