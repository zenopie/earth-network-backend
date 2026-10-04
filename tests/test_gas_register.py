"""/gas/register end to end: the grant, what is stored, once per passport in
30 days, the daily caps, failures of the shield, and the gas-check command.

The chain's verdict is stood in for (conftest chain_says); test_gascheck_live
runs the real command against a chain when EARTHD_BIN and GAS_CHECK_LIVE_MSG
point at one.
"""
import json
import os
import sqlite3
import time

import pytest

import config
from routers import gas
from services import chain, gascheck, replay
from services.zk import privacy
from tests.gas_fixtures import B64, CT_ANML, CT_ERTH, CT_GAS, NF_HEX, PC_GAS, REFERRAL, b64, body, field_b64, reg_body


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


def test_a_referral_reaches_gas_check_as_msg_register_fields(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body(**REFERRAL)).status_code == 200
    asked = chain_says["asked"][0]
    # MsgRegister affiliate_handle (15) in proto JSON, exactly as sent; no
    # referrer address, no referral note fields.
    assert asked["affiliate_handle"] == "amy-2"
    assert [k for k in asked if k.startswith("affiliate")] == ["affiliate_handle"]
    assert shields == [(PC_GAS, CT_GAS)]


def test_no_referral_sends_no_affiliate_fields(client, shields, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    assert not any(k.startswith("affiliate") for k in chain_says["asked"][0])


def test_a_handle_the_chain_says_is_not_live_is_a_refusal(client, shields, chain_says):
    chain_says["registration"] = {"ok": False, "error": 'affiliate_handle "amy-2": affiliate_handle is not a live handle'}
    resp = client.post("/gas/register", json=reg_body(**REFERRAL))
    assert resp.status_code == 403 and "not a live handle" in resp.json()["message"]
    assert shields == []
    from routers import gas
    assert gas._refusal_kind(chain_says["registration"]["error"]) == "affiliate"


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


def _granted(grant_id: str, days_ago: float):
    replay._db().execute("INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, '', ?)",
                         (grant_id, int(time.time() - days_ago * 86400)))
    replay._db().commit()


def test_a_month_rollover_is_not_a_second_grant(client, shields, chain_says):
    """A grant on the 31st and one on the 1st are within one 30-day window.
    Any id under the passport's prefix counts, :YYYY-MM included."""
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


def test_replay_rows_past_every_window_are_pruned(client, monkeypatch):
    import time

    from services import replay

    assert replay.KEEP_SECONDS >= gas.GRANT_ONCE_PER_SECONDS + 86400
    monkeypatch.setattr(replay, "_pruned_at", 0.0)
    db = replay._db()
    now = int(time.time())
    db.executemany("INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES (?, '', ?)",
                   [("passport:aa:2026-08-01", now - 40 * 86400), ("passport:bb:2026-09-05", now - 29 * 86400)])
    db.commit()
    assert replay.claim("passport:cc:2026-10-03", prefix="passport:", max_per_day=10)
    ids = {r[0] for r in db.execute("SELECT transaction_id FROM used_transactions")}
    assert ids == {"passport:bb:2026-09-05", "passport:cc:2026-10-03"}
    # Throttled: not again within the hour.
    db.execute("INSERT INTO used_transactions (transaction_id, address, granted_at) VALUES ('passport:dd:x', '', ?)",
               (now - 40 * 86400,))
    db.commit()
    assert replay.claim("passport:ee:2026-10-03", prefix="passport:", max_per_day=10)
    assert db.execute("SELECT 1 FROM used_transactions WHERE transaction_id = 'passport:dd:x'").fetchone()


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


def test_shield_dust_refuses_a_ciphertext_the_chain_would():
    import asyncio
    with pytest.raises(ValueError):
        asyncio.run(chain.shield_dust(PC_GAS, b"x" * 176))


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
