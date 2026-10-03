"""The stake note tree over recorded chain blocks: indexing, refusals, verification, /privacy/stake."""
import asyncio
import base64
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy as privacy_router
from services.privacy import events, verify
from services.privacy.indexer import Halted, Indexer
from services.privacy.store import Inconsistent, Store
from tests.privacy_fixtures import ChainClient, FakeRPC, seed_chain
from tests.stake_fixtures import STAKE_SCENARIOS, scenario, summary


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())


def _index(path: str, sc: dict):
    store = Store(path)
    rpc = FakeRPC(sc)
    sync(Indexer(store, rpc, batch=4))
    return store, rpc


@pytest.mark.parametrize("name", STAKE_SCENARIOS)
def test_stake_tree_is_indexed_and_rebuilds(tmp_path, name):
    sc = scenario(name)
    want = summary(sc)
    assert any("spc" in a for _, a in want["notes"]) and any("ciphertext" in a for _, a in want["notes"]), \
        "the scenario mints stake notes and creates them by proof"
    assert want["nullifiers"] and want["roots"]
    store, rpc = _index(str(tmp_path / "i.db"), sc)
    last = sc["blocks"][-1]
    assert store.stake_counts() == (last["stake_tree_size"], len(want["nullifiers"]))
    rows = store.conn.execute("SELECT height, root, tree_size FROM stake_roots ORDER BY height").fetchall()
    assert [(h, r.hex(), n) for h, r, n in rows] == want["roots"]
    for h, a in want["notes"]:
        row = store.conn.execute("SELECT height, cm, ciphertext, denom, amount, spc FROM stake_notes WHERE position = ?",
                                 (int(a["position_id"]),)).fetchone()
        assert row[0] == h and row[1].hex() == a["commitment"]
        if "spc" in a:
            assert row[2] is None and (row[3], row[4], row[5].hex()) == (a["denom"], a["amount"], a["spc"])
            assert row[3].startswith(("derth/", "unbond/"))
        else:
            assert base64.b64encode(row[2]).decode() == a["ciphertext"] and row[3:] == (None, None, None)
    rep = verify.rebuild(store.conn, all_roots=True)
    asyncio.run(verify.check_chain(rep, rpc))
    assert rep.ok, rep.errors
    assert rep.stake_root.hex() == last["stake_latest_root"]
    assert rep.stake_minted_checked == sum("spc" in a for _, a in want["notes"])


@pytest.fixture
def indexed(tmp_path):
    return _index(str(tmp_path / "i.db"), scenario())


def test_a_tampered_minted_amount_is_caught(indexed):
    store, _ = indexed
    (pos,) = store.conn.execute("SELECT MIN(position) FROM stake_notes WHERE denom IS NOT NULL").fetchone()
    store.conn.execute("UPDATE stake_notes SET amount = '999' WHERE position = ?", (pos,))
    rep = verify.rebuild(store.conn)
    assert any(f"stake note {pos}" in e for e in rep.errors)


def test_a_tampered_stake_commitment_is_caught_against_the_chain(indexed):
    store, rpc = indexed
    (pos,) = store.conn.execute("SELECT MIN(position) FROM stake_notes WHERE denom IS NULL").fetchone()
    store.conn.execute("UPDATE stake_notes SET cm = ? WHERE position = ?", (bytes(31) + b"\x05", pos))
    rep = verify.rebuild(store.conn, all_roots=True)
    assert any("stake root" in e for e in rep.errors)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("stake tree: chain root" in e for e in rep.errors)


def _stake_events(sc: dict, type_: str):
    for b in sc["blocks"]:
        r = b["block_results"]
        for e in [e for tx in r.get("txs_results") or [] for e in tx.get("events") or []] + (r.get("finalize_block_events") or []):
            if e["type"] == type_:
                yield e


def test_stake_notes_out_of_sequence_are_refused(tmp_path):
    sc = copy.deepcopy(scenario())
    first = next(_stake_events(sc, "shieldedstaking_stake_note"))
    next(a for a in first["attributes"] if a["key"] == "position_id")["value"] = "1"
    with pytest.raises(Halted, match="stake note at position 1, expected 0"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_stake_root_at_the_wrong_size_is_refused(tmp_path):
    sc = copy.deepcopy(scenario())
    root = next(_stake_events(sc, "shieldedstaking_stake_root"))
    a = next(a for a in root["attributes"] if a["key"] == "tree_size")
    a["value"] = str(int(a["value"]) + 1)
    with pytest.raises(Halted, match="stake root at size"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_stake_nullifier_twice_is_refused(indexed):
    store, _ = indexed
    nf = store.conn.execute("SELECT nf FROM stake_nullifiers LIMIT 1").fetchone()[0]
    d = events.BlockDelta(height=store.last_height() + 1, time=0, hash="X", stake_nullifiers=[nf])
    with pytest.raises(Inconsistent, match="stake nullifier"):
        store.apply(d)


def test_stake_notes_missing_from_the_index_halt(tmp_path):
    """Stake notes imported at genesis emit no events: the size check catches them."""
    sc = copy.deepcopy(scenario())
    for b in sc["blocks"]:
        b["stake_tree_size"] = b.get("stake_tree_size", 0) + 1
    with pytest.raises(Halted, match="stake notes"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


@pytest.mark.parametrize("attrs", [
    {"position_id": "0", "commitment": "11" * 32},  # neither
    {"position_id": "0", "commitment": "11" * 32, "ciphertext": "", "denom": "d", "amount": "1", "spc": "22" * 32},  # both
    {"position_id": "0", "commitment": "11" * 32, "denom": "d", "amount": "1"},  # no spc
    {"position": "0", "commitment": "11" * 32, "ciphertext": ""},  # x/shielded's key, not position_id
    {"position_id": "0", "commitment": "11" * 32, "ciphertext": "!!"},
])
def test_malformed_stake_notes_are_refused(attrs):
    res = {"height": "1", "txs_results": [{"code": 0, "events": [
        {"type": "shieldedstaking_stake_note", "attributes": [{"key": k, "value": v} for k, v in attrs.items()]}]}]}
    with pytest.raises(events.EventError):
        events.parse_block(1, 0, "H", res)


@pytest.fixture
def api(indexed, monkeypatch):
    store, _ = indexed
    monkeypatch.setattr(config, "INDEX_DB", store.path)
    app = FastAPI()
    app.include_router(privacy_router.router)
    return ChainClient(TestClient(app))


def test_stake_notes_stream(api):
    want = summary(scenario())
    seen, pos = [], 0
    while True:
        r = api.get("/privacy/stake/notes", params={"from_pos": pos, "limit": 2})
        body = r.json()
        assert body["fields"] == ["position", "height", "cm", "ciphertext", "denom", "amount", "spc"]
        assert ("immutable" in r.headers["cache-control"]) == body["complete"]
        seen += body["notes"]
        if not body["complete"]:
            break
        pos = body["next_pos"]
    assert [n[0] for n in seen] == list(range(len(want["notes"])))
    for (p, h, cm, ct, denom, amount, spc), (wh, a) in zip(seen, want["notes"]):
        assert (h, cm) == (wh, a["commitment"])
        if "spc" in a:
            assert ct is None and (denom, amount, spc) == (a["denom"], a["amount"], a["spc"])
        else:
            assert ct == a["ciphertext"] and denom is None and amount is None and spc is None


def test_stake_nullifiers_and_roots_streams(api):
    want = summary(scenario())
    body = api.get("/privacy/stake/nullifiers").json()
    assert [(h, nf) for h, nfs in body["blocks"] for nf in nfs] == want["nullifiers"]
    assert body["next_height"] == body["synced_height"] + 1 and body["complete"] is False
    got, h = [], 0
    while True:
        r = api.get("/privacy/stake/roots", params={"from_height": h, "limit": 1})
        body = r.json()
        assert body["fields"] == ["height", "root", "tree_size", "time"]
        assert ("immutable" in r.headers["cache-control"]) == body["complete"]
        got += [tuple(x[:3]) for x in body["roots"]]
        if not body["complete"]:
            break
        h = body["next_height"]
    assert got == want["roots"]
    assert body["next_height"] == body["synced_height"] + 1


def test_status_and_latest_roots_carry_the_stake_tree(api):
    sc = scenario()
    want = summary(sc)
    s = api.get("/privacy/status").json()
    assert (s["stake_notes"], s["stake_nullifiers"]) == (sc["blocks"][-1]["stake_tree_size"], len(want["nullifiers"]))
    latest = api.get("/privacy/roots/latest").json()["stake"]
    assert (latest["height"], latest["root"], latest["tree_size"]) == want["roots"][-1]


def test_empty_stake_streams(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INDEX_DB", str(tmp_path / "empty.db"))
    seed_chain(config.INDEX_DB)
    app = FastAPI()
    app.include_router(privacy_router.router)
    c = ChainClient(TestClient(app))
    assert c.get("/privacy/stake/notes").json()["notes"] == []
    assert c.get("/privacy/stake/nullifiers").json()["blocks"] == []
    assert c.get("/privacy/stake/roots").json()["roots"] == []
    assert c.get("/privacy/roots/latest").json()["stake"] is None
