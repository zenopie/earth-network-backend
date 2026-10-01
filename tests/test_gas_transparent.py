"""The transparent grant: /gas/transparent pays an address a live human names.

The proof is real (tests/fixtures/gas_transparent/membership.json, the chain's
x/personhood/testdata/gas proof: scope GasScope(202610), signal bound to its
address on earth-1); the chain's verdict on it is stood in for, except in
test_gascheck_membership_live, which runs the real command against a chain
when EARTHD_BIN and GAS_CHECK_LIVE_MEMBERSHIP point at one.
"""
import asyncio
import base64
import json
import os
import sqlite3
import stat

import pytest

import config
from routers import gas
from services import chain, gascheck, replay

FIXTURE = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "gas_transparent", "membership.json")))
NF_HEX = base64.b64decode(FIXTURE["nullifier"]).hex()


def body(**over):
    b = {k: FIXTURE[k] for k in ("address", "proof", "root", "nullifier", "max_activation", "month")}
    b.update(over)
    return b


@pytest.fixture(autouse=True)
def october(monkeypatch):
    monkeypatch.setattr(gas, "_this_month", lambda: 202610)


@pytest.fixture
def chain_says(monkeypatch):
    """Sets gas-check's verdict; records what it was asked."""
    state = {"verdict": {"ok": True, "nullifier": NF_HEX, "height": 7}, "asked": []}

    async def membership(m, address, month, max_activation):
        state["asked"].append((m, address, month, max_activation))
        if isinstance(state["verdict"], Exception):
            raise state["verdict"]
        return state["verdict"]

    monkeypatch.setattr(gascheck, "membership", membership)
    return state


def test_grant_sends_dust_to_the_address(client, sends, chain_says):
    resp = client.post("/gas/transparent", json=body())
    assert resp.status_code == 200, resp.text
    assert resp.json()["tx_hash"] == "HASH1"
    assert sends == [FIXTURE["address"]]
    m, address, month, max_act = chain_says["asked"][0]
    assert m == {"proof": FIXTURE["proof"], "root": FIXTURE["root"], "nullifier": FIXTURE["nullifier"]}
    assert (address, month, max_act) == (FIXTURE["address"], 202610, FIXTURE["max_activation"])


def test_month_defaults_to_this_one(client, sends, chain_says):
    b = body()
    del b["month"]
    assert client.post("/gas/transparent", json=b).status_code == 200
    assert chain_says["asked"][0][2] == 202610


def test_stores_only_the_nullifier_and_month(client, sends, chain_says):
    assert client.post("/gas/transparent", json=body()).status_code == 200
    rows = sqlite3.connect(config.STATE_DB).execute("SELECT transaction_id, address FROM used_transactions").fetchall()
    assert rows == [(f"gas-transparent:{NF_HEX}:2026-10", "")]


def test_once_per_nullifier_per_month_whatever_the_address(client, sends, chain_says):
    assert client.post("/gas/transparent", json=body()).status_code == 200
    other = "earth1qqqsyqcyq5rqwzqfpg9scrgwpugpzysncc2uls"
    resp = client.post("/gas/transparent", json=body(address=other))
    assert resp.status_code == 409
    assert sends == [FIXTURE["address"]]


def test_next_month_is_a_new_grant(client, sends, chain_says, monkeypatch):
    assert client.post("/gas/transparent", json=body()).status_code == 200
    monkeypatch.setattr(gas, "_this_month", lambda: 202611)
    # Same nullifier string stood in: a real proof for November has another.
    assert client.post("/gas/transparent", json=body(month=202611)).status_code == 200
    assert len(sends) == 2


def test_another_month_is_refused_before_asking(client, sends, chain_says):
    assert client.post("/gas/transparent", json=body(month=202609)).status_code == 400
    assert chain_says["asked"] == []


def test_daily_cap_applies(client, sends, chain_says, monkeypatch):
    monkeypatch.setattr(config, "GRANT_MAX_PER_DAY", 1)
    assert client.post("/gas/transparent", json=body()).status_code == 200
    nf2 = (5).to_bytes(32, "big")
    chain_says["verdict"] = {"ok": True, "nullifier": nf2.hex()}
    resp = client.post("/gas/transparent", json=body(nullifier=base64.b64encode(nf2).decode()))
    assert resp.status_code == 429


def test_refusal_carries_the_chains_reason(client, sends, chain_says):
    chain_says["verdict"] = {"ok": False, "error": "unknown identity root"}
    resp = client.post("/gas/transparent", json=body())
    assert resp.status_code == 403 and "unknown identity root" in resp.json()["message"]
    assert sends == []


def test_unavailable_is_503(client, sends, chain_says):
    chain_says["verdict"] = gascheck.Unavailable("node down")
    assert client.post("/gas/transparent", json=body()).status_code == 503
    assert sends == []


def test_a_verdict_for_another_nullifier_pays_nothing(client, sends, chain_says):
    chain_says["verdict"] = {"ok": True, "nullifier": "00" * 32}
    assert client.post("/gas/transparent", json=body()).status_code == 503
    assert sends == []


@pytest.mark.parametrize("over", [
    {"address": "cosmos1abc"},
    {"proof": "not base64!"},
    {"proof": ""},
    {"root": base64.b64encode(b"\x01" * 31).decode()},
    {"nullifier": base64.b64encode(b"\xff" * 32).decode()},  # not canonical
    {"max_activation": -1},
])
def test_malformed_is_refused_before_asking(client, sends, chain_says, over):
    assert client.post("/gas/transparent", json=body(**over)).status_code == 400
    assert chain_says["asked"] == []


def test_failed_send_gives_the_nullifier_back(client, chain_says, monkeypatch):
    async def boom(address):
        raise RuntimeError("insufficient funds")

    monkeypatch.setattr(chain, "send_dust", boom)
    assert client.post("/gas/transparent", json=body()).status_code == 502

    async def ok(address):
        return "H"

    monkeypatch.setattr(chain, "send_dust", ok)
    assert client.post("/gas/transparent", json=body()).status_code == 200


def test_unresolved_send_keeps_the_nullifier(client, chain_says, monkeypatch):
    async def unresolved(address):
        raise chain.SendUnresolved("ABC", TimeoutError())

    monkeypatch.setattr(chain, "send_dust", unresolved)
    resp = client.post("/gas/transparent", json=body())
    assert resp.status_code == 202 and resp.json()["tx_hash"] == "ABC"
    assert client.post("/gas/transparent", json=body()).status_code == 409


def test_gascheck_membership_runs_earthd(monkeypatch, tmp_path):
    """The command line and stdin gas-check membership gets, through a stand-in earthd."""
    log = tmp_path / "args.json"
    fake = tmp_path / "earthd"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'stdin': json.load(sys.stdin)}}, open({str(log)!r}, 'w'))\n"
        "print(json.dumps({'ok': True, 'nullifier': 'ab', 'height': 3}))\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(config, "EARTHD_BIN", str(fake))
    m = {"proof": FIXTURE["proof"], "root": FIXTURE["root"], "nullifier": FIXTURE["nullifier"]}
    verdict = asyncio.run(gascheck.membership(m, FIXTURE["address"], 202610, FIXTURE["max_activation"]))
    assert verdict == {"ok": True, "nullifier": "ab", "height": 3}
    got = json.load(open(log))
    assert got["stdin"] == m
    argv = got["argv"]
    assert argv[:2] == ["gas-check", "membership"]
    assert argv[argv.index("--address") + 1] == FIXTURE["address"]
    assert argv[argv.index("--month") + 1] == "202610"
    assert argv[argv.index("--max-activation") + 1] == str(FIXTURE["max_activation"])


@pytest.mark.skipif(not (os.getenv("EARTHD_BIN") and os.getenv("GAS_CHECK_LIVE_MEMBERSHIP")),
                    reason="set EARTHD_BIN (a privacy-chain earthd) and GAS_CHECK_LIVE_MEMBERSHIP "
                           "(a JSON file shaped like the fixture, proved against that chain)")
def test_gascheck_membership_live(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "EARTHD_BIN", os.environ["EARTHD_BIN"])
    monkeypatch.setattr(config, "EARTHD_HOME", str(tmp_path))
    f = json.load(open(os.environ["GAS_CHECK_LIVE_MEMBERSHIP"]))
    m = {k: f[k] for k in ("proof", "root", "nullifier")}
    verdict = asyncio.run(gascheck.membership(m, f["address"], f["month"], f["max_activation"]))
    assert "ok" in verdict
