"""The proof-backed grants: /gas/register and /gas/human.

The chain's verdict is stood in for here; what is under test is what the
backend does with it — the limits, the keys it grants under, and telling a
refusal apart from a check that could not be made. test_gascheck_live runs the
real command against the live chain when EARTHD_BIN points at one.
"""
import base64
import json
import os
import subprocess

import pytest

import config
from services import gascheck
from tests.conftest import ADDRESS

OTHER = "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"
B64 = base64.b64encode(b"x").decode()


def reg_body(address=ADDRESS):
    return {"address": address, "proof": B64, "public_signals": ["1", "2"],
            "signature_algorithm": "lean_poa", "dsc_der": B64}


@pytest.fixture
def chain_says(monkeypatch):
    """Sets the verdict gas-check returns; records the MsgRegister it was asked about."""
    state = {"registration": {"ok": True, "nullifier": "aa" * 32, "switched": False},
             "human": {"ok": True, "nullifier": "bb" * 32}, "asked": []}

    async def registration(msg):
        state["asked"].append(msg)
        if isinstance(state["registration"], Exception):
            raise state["registration"]
        return state["registration"]

    async def human(address):
        if isinstance(state["human"], Exception):
            raise state["human"]
        return state["human"]

    monkeypatch.setattr(gascheck, "registration", registration)
    monkeypatch.setattr(gascheck, "human", human)
    return state


def test_register_grant(client, sends, chain_says):
    resp = client.post("/gas/register", json=reg_body())
    assert resp.status_code == 200, resp.text
    assert sends == [ADDRESS]
    assert chain_says["asked"][0]["creator"] == ADDRESS
    assert chain_says["asked"][0]["proof"] == B64


def test_register_is_once_per_passport_whatever_the_wallet(client, sends, chain_says):
    assert client.post("/gas/register", json=reg_body()).status_code == 200
    # Same passport (nullifier), a fresh wallet: no second grant this month.
    assert client.post("/gas/register", json=reg_body(OTHER)).status_code == 409
    assert sends == [ADDRESS]


def test_register_refusal_carries_the_chains_reason(client, sends, chain_says):
    chain_says["registration"] = {"ok": False, "error": "passport expired"}
    resp = client.post("/gas/register", json=reg_body())
    assert resp.status_code == 403
    assert "passport expired" in resp.json()["message"]
    assert sends == []


def test_register_unavailable_is_503_not_a_refusal(client, sends, chain_says):
    chain_says["registration"] = gascheck.Unavailable("node down")
    assert client.post("/gas/register", json=reg_body()).status_code == 503
    assert sends == []


def test_register_rejects_non_base64(client, sends, chain_says):
    body = reg_body()
    body["proof"] = "not base64!"
    assert client.post("/gas/register", json=body).status_code == 400
    assert chain_says["asked"] == []


def test_human_grant_once_per_person_per_day(client, sends, chain_says):
    assert client.post("/gas/human", json={"address": ADDRESS}).status_code == 200
    assert client.post("/gas/human", json={"address": ADDRESS}).status_code == 409
    # The same person from another wallet is the same person.
    assert client.post("/gas/human", json={"address": OTHER}).status_code == 409
    assert sends == [ADDRESS]


def test_human_refused_when_not_registered(client, sends, chain_says):
    chain_says["human"] = {"ok": False, "error": "address is not a registered human"}
    assert client.post("/gas/human", json={"address": ADDRESS}).status_code == 403
    assert sends == []


def test_human_unavailable(client, sends, chain_says):
    chain_says["human"] = gascheck.Unavailable("timeout")
    assert client.post("/gas/human", json={"address": ADDRESS}).status_code == 503


def test_gascheck_missing_binary_is_unavailable(monkeypatch):
    import asyncio

    monkeypatch.setattr(config, "EARTHD_BIN", "/nonexistent/earthd")
    with pytest.raises(gascheck.Unavailable):
        asyncio.run(gascheck.human(ADDRESS))


@pytest.mark.skipif(not os.getenv("EARTHD_BIN"), reason="set EARTHD_BIN to an earthd with gas-check to run against the live chain")
def test_gascheck_live(monkeypatch, tmp_path):
    import asyncio

    monkeypatch.setattr(config, "EARTHD_BIN", os.environ["EARTHD_BIN"])
    monkeypatch.setattr(config, "EARTHD_HOME", str(tmp_path))
    registered = asyncio.run(gascheck.human("earth1dlu00sy3kxanknuu0cfum4un7tddxj23zdt3pd"))
    assert registered["ok"] is True
    assert asyncio.run(gascheck.human(OTHER))["ok"] is False
