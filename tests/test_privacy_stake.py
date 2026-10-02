"""The stake note tree: indexing, refusals, verification and /privacy/stake."""
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
from tests.privacy_fixtures import FakeRPC
from tests.stake_fixtures import DERTH, UNBOND, with_stake


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())


@pytest.fixture
def sc():
    return with_stake()


@pytest.fixture
def indexed(tmp_path, sc):
    store = Store(str(tmp_path / "i.db"))
    rpc = FakeRPC(sc)
    sync(Indexer(store, rpc, batch=4))
    return store, rpc


def test_stake_tree_is_indexed_and_rebuilds(indexed, sc):
    store, rpc = indexed
    assert store.stake_counts() == (4, 1)
    rows = store.conn.execute("SELECT height, root, tree_size FROM stake_roots ORDER BY height").fetchall()
    assert [(h, r.hex(), n) for h, r, n in rows] == list(zip(sc["stake"]["heights"], sc["stake"]["roots"], [2, 4]))
    minted = store.conn.execute("SELECT denom, amount, ciphertext FROM stake_notes WHERE denom IS NOT NULL ORDER BY position").fetchall()
    assert minted == [(DERTH, "1000000", None), (UNBOND, "5", None)]
    created = store.conn.execute("SELECT denom, amount, spc, ciphertext FROM stake_notes WHERE denom IS NULL").fetchall()
    assert len(created) == 2 and all(r[:3] == (None, None, None) and r[3].startswith(b"stake ct") for r in created)
    rep = verify.rebuild(store.conn, all_roots=True)
    asyncio.run(verify.check_chain(rep, rpc))
    assert rep.ok, rep.errors
    assert rep.stake_size == 4 and rep.stake_root.hex() == sc["stake"]["roots"][-1]
    assert rep.stake_minted_checked == 2


def test_a_tampered_minted_amount_is_caught(indexed):
    store, _ = indexed
    store.conn.execute("UPDATE stake_notes SET amount = '999' WHERE position = 0")
    rep = verify.rebuild(store.conn)
    assert any("stake note 0" in e for e in rep.errors)


def test_a_tampered_stake_commitment_is_caught_against_the_chain(indexed):
    store, rpc = indexed
    store.conn.execute("UPDATE stake_notes SET cm = ? WHERE position = 3", (bytes(31) + b"\x05",))
    rep = verify.rebuild(store.conn, all_roots=True)
    assert any("stake root" in e for e in rep.errors)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("stake tree: chain root" in e for e in rep.errors)


def test_stake_notes_out_of_sequence_are_refused(tmp_path, sc):
    h = sc["stake"]["heights"][0]
    blk = next(b for b in sc["blocks"] if b["height"] == h)
    txs = blk["block_results"]["txs_results"]
    txs[-1], txs[-2] = txs[-2], txs[-1]
    with pytest.raises(Halted, match="stake note at position"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_stake_root_at_the_wrong_size_is_refused(tmp_path, sc):
    h = sc["stake"]["heights"][1]
    blk = next(b for b in sc["blocks"] if b["height"] == h)
    for e in blk["block_results"]["finalize_block_events"]:
        if e["type"] == "shieldedstaking_stake_root":
            next(a for a in e["attributes"] if a["key"] == "tree_size")["value"] = "3"
    with pytest.raises(Halted, match="stake root at size 3"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_stake_nullifier_twice_is_refused(indexed, sc):
    store, _ = indexed
    d = events.BlockDelta(height=store.last_height() + 1, time=0, hash="X",
                          stake_nullifiers=[bytes.fromhex(sc["stake"]["nullifier"])])
    with pytest.raises(Inconsistent, match="stake nullifier"):
        store.apply(d)


def test_stake_notes_missing_from_the_index_halt(tmp_path, sc):
    """Stake notes imported at genesis emit no events: the size check catches them."""
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
    return TestClient(app)


def test_stake_notes_stream(api, sc):
    seen, pos = [], 0
    while True:
        r = api.get("/privacy/stake/notes", params={"from_pos": pos, "limit": 3})
        body = r.json()
        assert body["fields"] == ["position", "height", "cm", "ciphertext", "denom", "amount", "spc"]
        assert ("immutable" in r.headers["cache-control"]) == body["complete"]
        seen += body["notes"]
        if not body["complete"]:
            break
        pos = body["next_pos"]
    assert [n[0] for n in seen] == [0, 1, 2, 3]
    p, h, cm, ct, denom, amount, spc = seen[0]
    assert h == sc["stake"]["heights"][0] and len(bytes.fromhex(cm)) == 32
    assert ct is None and denom == DERTH and amount == "1000000" and len(bytes.fromhex(spc)) == 32
    p, h, cm, ct, denom, amount, spc = seen[3]
    assert base64.b64decode(ct) == b"stake ct 2" and denom is None and amount is None and spc is None


def test_stake_nullifiers_and_roots_streams(api, sc):
    body = api.get("/privacy/stake/nullifiers").json()
    assert body["blocks"] == [[sc["stake"]["heights"][1], [sc["stake"]["nullifier"]]]]
    assert body["next_height"] == body["synced_height"] + 1 and body["complete"] is False
    r = api.get("/privacy/stake/roots", params={"limit": 1})
    body = r.json()
    assert body["fields"] == ["height", "root", "tree_size", "time"]
    assert body["complete"] and "immutable" in r.headers["cache-control"]
    assert [x[:3] for x in body["roots"]] == [[sc["stake"]["heights"][0], sc["stake"]["roots"][0], 2]]
    body = api.get("/privacy/stake/roots", params={"from_height": body["next_height"]}).json()
    assert [x[:3] for x in body["roots"]] == [[sc["stake"]["heights"][1], sc["stake"]["roots"][1], 4]]
    assert not body["complete"] and body["next_height"] == body["synced_height"] + 1


def test_status_and_latest_roots_carry_the_stake_tree(api, sc):
    s = api.get("/privacy/status").json()
    assert (s["stake_notes"], s["stake_nullifiers"]) == (4, 1)
    latest = api.get("/privacy/roots/latest").json()["stake"]
    assert latest["root"] == sc["stake"]["roots"][1] and latest["tree_size"] == 4
    assert latest["height"] == sc["stake"]["heights"][1]


def test_empty_stake_streams(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INDEX_DB", str(tmp_path / "empty.db"))
    app = FastAPI()
    app.include_router(privacy_router.router)
    c = TestClient(app)
    assert c.get("/privacy/stake/notes").json()["notes"] == []
    assert c.get("/privacy/stake/nullifiers").json()["blocks"] == []
    assert c.get("/privacy/stake/roots").json()["roots"] == []
    assert c.get("/privacy/roots/latest").json()["stake"] is None
