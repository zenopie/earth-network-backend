"""Shared fixtures: fresh limiter and replay state for every test, the gas
router app, gas-check and chain stand-ins, and a /privacy index of notes."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from routers import gas  # noqa: E402
from routers import privacy as privacy_router  # noqa: E402
from services import dsccommit, gascheck, knowndsc, pow, ratelimit, replay  # noqa: E402
from services.privacy import store as store_mod  # noqa: E402
from services.privacygate import PrivacyGate  # noqa: E402
from services.zk import privacy  # noqa: E402
from tests.gas_fixtures import gas_app  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(replay, "_conn", None)
    ratelimit.reset()
    pow.reset()
    knowndsc.reset()
    dsccommit.reset()
    yield
    if replay._conn is not None:
        replay._conn.close()


@pytest.fixture
def client():
    return TestClient(gas_app())


@pytest.fixture
def shields(monkeypatch):
    """Records every (pc, ciphertext) a gas note is shielded to, in place of the chain."""
    sent: list[tuple[bytes, bytes]] = []

    async def fake_shield(pc: bytes, ciphertext: bytes) -> str:
        sent.append((pc, ciphertext))
        return f"HASH{len(sent)}"

    monkeypatch.setattr(gas.chain, "shield_dust", fake_shield)
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


@pytest.fixture
def chain(monkeypatch):
    """gas-check stand-in: nullifiers in `refuse` get that error; records priority."""
    state = {"refuse": {}, "priority": []}

    async def registration(msg, priority=False):
        nf = int(msg["public_signals"][2])
        state["priority"].append(priority)
        if nf in state["refuse"]:
            return {"ok": False, "error": state["refuse"][nf]}
        return {"ok": True, "nullifier": privacy.field_bytes(nf).hex(), "switched": False}

    async def shield(pc, ct):
        return "HASH"

    monkeypatch.setattr(gascheck, "registration", registration)
    monkeypatch.setattr(gas.chain, "shield_dust", shield)
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    monkeypatch.setattr(config, "POW_RESERVED_BITS", 6)
    monkeypatch.setattr(config, "POW_SHED_BITS", 8)
    monkeypatch.setattr(config, "POW_LOAD_EXTRA_BITS", 0)
    return state


@pytest.fixture
def notes_index(tmp_path, monkeypatch):
    db = str(tmp_path / "idx.db")
    monkeypatch.setattr(config, "INDEX_DB", db)
    c = store_mod.connect(db)
    c.execute("BEGIN")
    c.executemany("INSERT INTO meta VALUES (?,?)",
                  [("chain_id", "earth-1"), ("genesis_hash", "ab" * 32), ("last_height", "10"),
                   ("verified_height", "10")])
    c.execute("INSERT INTO blocks VALUES (1,'x',0)")
    c.executemany("INSERT INTO notes (position, cm, ciphertext, height, amount) VALUES (?,?,?,?,?)",
                  ((i, os.urandom(32), os.urandom(177), 1, None) for i in range(5500)))
    c.execute("COMMIT")
    c.close()
    app = FastAPI()
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(PrivacyGate)
    app.include_router(privacy_router.router)
    return TestClient(app)
