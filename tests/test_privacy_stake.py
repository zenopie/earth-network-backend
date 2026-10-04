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
from services.zk.indexed import EMPTY_ROOT, IndexedTree
from tests.stake_fixtures import STAKE_SCENARIOS, VOTE_SCENARIO, scenario, summary


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
    assert any("spc" in a for _, a in want["notes"]) and any("spc" not in a for _, a in want["notes"]), \
        "the scenario mints stake notes and creates them by proof"
    assert all("ciphertext" in a for _, a in want["notes"]), "every stake note carries a ciphertext"
    assert all(len(base64.b64decode(a["ciphertext"])) == 177 for _, a in want["notes"] if "spc" in a), \
        "a minted stake note's is its 177-byte blind stake ciphertext"
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
        assert base64.b64encode(row[2]).decode() == a["ciphertext"]
        if "spc" in a:
            assert (row[3], row[4], row[5].hex()) == (a["denom"], a["amount"], a["spc"])
            # Only derth/<valoper> notes since 48b631c (the unbond/ claim
            # notes are gone: an undelegation pays out as pool notes).
            assert row[3].startswith("derth/")
        else:
            assert row[3:] == (None, None, None)
    nfs = store.conn.execute("SELECT idx, nf, height FROM stake_nullifiers ORDER BY idx").fetchall()
    assert [(i, nf.hex(), h) for i, nf, h in nfs] == want["nf_index"]
    assert [i for i, _, _ in want["nf_index"]] == list(range(1, len(want["nf_index"]) + 1))
    assert store.stake_nf_size() == last["stake_nf_tree_size"]
    rep = verify.rebuild(store.conn, all_roots=True)
    asyncio.run(verify.check_chain(rep, rpc))
    assert rep.ok, rep.errors
    assert rep.stake_root.hex() == last["stake_latest_root"]
    assert (rep.stake_nf_size, rep.stake_nf_root.hex()) == (
        last["stake_nf_tree_size"], last["stake_nf_current_root"] or EMPTY_ROOT.to_bytes(32, "big").hex())
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
    d = events.BlockDelta(height=store.last_height() + 1, time=0, hash="X",
                          stake_nullifiers=[events.StakeNullifier(nf, store.stake_nf_size())])
    with pytest.raises(Inconsistent, match="spent twice"):
        store.apply(d)


@pytest.mark.parametrize("shift,match", [(1, "expected 1"), (-1, "expected 1")])
def test_a_stake_nullifier_index_out_of_sequence_halts(tmp_path, shift, match):
    """A gap or a repeated leaf index: the tree wallets rebuild would be wrong."""
    sc = copy.deepcopy(scenario())
    first = next(_stake_events(sc, "shieldedstaking_stake_nullifier"))
    a = next(a for a in first["attributes"] if a["key"] == "index")
    a["value"] = str(int(a["value"]) + shift)
    with pytest.raises(Halted, match=f"stake nullifier .* at leaf {1 + shift}, {match}"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_repeated_stake_nullifier_index_halts(tmp_path):
    sc = copy.deepcopy(scenario(VOTE_SCENARIO))
    evs = list(_stake_events(sc, "shieldedstaking_stake_nullifier"))
    assert len(evs) >= 2
    next(a for a in evs[1]["attributes"] if a["key"] == "index")["value"] = "1"
    with pytest.raises(Halted, match="at leaf 1, expected 2"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_a_stake_nullifier_without_its_index_is_refused():
    res = {"height": "1", "txs_results": [{"code": 0, "events": [
        {"type": "shieldedstaking_stake_nullifier", "attributes": [{"key": "nullifier", "value": "11" * 32}]}]}]}
    with pytest.raises(events.EventError, match="no index"):
        events.parse_block(1, 0, "H", res)


def test_stake_nullifiers_missing_from_the_index_halt(tmp_path):
    """Nullifiers imported at genesis emit no events: the nullifier tree size check catches them."""
    sc = copy.deepcopy(scenario())
    for b in sc["blocks"]:
        b["stake_nf_tree_size"] = b["stake_nf_tree_size"] + 1 if b["stake_nf_tree_size"] else 2
    with pytest.raises(Halted, match="stake nullifier tree of"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


# --- the stake nullifier tree at proposal snapshots ----------------------------

@pytest.fixture
def voted(tmp_path):
    return _index(str(tmp_path / "v.db"), scenario(VOTE_SCENARIO))


def test_snapshots_are_indexed_and_their_nf_roots_rebuild(voted):
    store, rpc = voted
    want = summary(scenario(VOTE_SCENARIO))
    assert len(want["snapshots"]) >= 2 and any(int(a["nf_size"]) >= 2 for _, a in want["snapshots"])
    rows = store.conn.execute("SELECT proposal_id, height, root, tree_size, nf_root, nf_size FROM stake_snapshots"
                              " ORDER BY proposal_id").fetchall()
    assert [(p, h, r.hex(), ts, nr.hex(), ns) for p, h, r, ts, nr, ns in rows] == [
        (int(a["proposal_id"]), h, a["root"], int(a["tree_size"]), a["nf_root"], int(a["nf_size"]))
        for h, a in want["snapshots"]]
    rep = verify.rebuild(store.conn)
    assert rep.snapshots_checked == len(want["snapshots"])
    asyncio.run(verify.check_chain(rep, rpc))
    assert rep.ok, rep.errors
    # Nullifiers spent after the snapshot: the tree grew past it.
    assert rep.stake_nf_size > max(int(a["nf_size"]) for _, a in want["snapshots"])


def test_a_wrong_snapshot_nf_root_is_caught(voted):
    store, _ = voted
    store.conn.execute("UPDATE stake_snapshots SET nf_root = ? WHERE proposal_id = 1", (bytes(31) + b"\x07",))
    rep = verify.rebuild(store.conn)
    assert any("proposal 1 snapshot" in e for e in rep.errors)


def test_a_reordered_stake_nullifier_tree_is_caught(voted):
    """Same values, other insertion order: another root (leaf positions are insertion order)."""
    store, rpc = voted
    a, b = store.conn.execute("SELECT idx, nf FROM stake_nullifiers ORDER BY idx LIMIT 2").fetchall()
    store.conn.execute("UPDATE stake_nullifiers SET nf = ? WHERE idx = ?", (bytes(32), a[0]))
    store.conn.execute("UPDATE stake_nullifiers SET nf = ? WHERE idx = ?", (a[1], b[0]))
    store.conn.execute("UPDATE stake_nullifiers SET nf = ? WHERE idx = ?", (b[1], a[0]))
    rep = verify.rebuild(store.conn)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("stake nullifier tree: chain root" in e for e in rep.errors)


def test_a_snapshot_past_the_indexed_nullifier_tree_is_refused(tmp_path):
    sc = copy.deepcopy(scenario(VOTE_SCENARIO))
    snap = next(_stake_events(sc, "shieldedstaking_snapshot"))
    next(a for a in snap["attributes"] if a["key"] == "nf_size")["value"] = "9"
    with pytest.raises(Halted, match="snapshot at nullifier tree size 9"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


def test_stake_notes_missing_from_the_index_halt(tmp_path):
    """Stake notes imported at genesis emit no events: the size check catches them."""
    sc = copy.deepcopy(scenario())
    for b in sc["blocks"]:
        b["stake_tree_size"] = b.get("stake_tree_size", 0) + 1
    with pytest.raises(Halted, match="stake notes"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


@pytest.mark.parametrize("attrs", [
    {"position_id": "0", "commitment": "11" * 32},  # no ciphertext
    {"position_id": "0", "commitment": "11" * 32, "denom": "d", "amount": "1", "spc": "22" * 32},  # minted, no ciphertext
    {"position_id": "0", "commitment": "11" * 32, "ciphertext": "", "denom": "d", "amount": "1"},  # no spc
    {"position_id": "0", "commitment": "11" * 32, "ciphertext": "", "denom": "", "amount": "1", "spc": "22" * 32},
    {"position": "0", "commitment": "11" * 32, "ciphertext": ""},  # x/shielded's key, not position_id
    {"position_id": "0", "commitment": "11" * 32, "ciphertext": "!!"},
])
def test_malformed_stake_notes_are_refused(attrs):
    res = {"height": "1", "txs_results": [{"code": 0, "events": [
        {"type": "shieldedstaking_stake_note", "attributes": [{"key": k, "value": v} for k, v in attrs.items()]}]}]}
    with pytest.raises(events.EventError):
        events.parse_block(1, 0, "H", res)


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (1, 2, 100, 1000))


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
        assert ct == a["ciphertext"]
        if "spc" in a:
            assert (denom, amount, spc) == (a["denom"], a["amount"], a["spc"])
        else:
            assert denom is None and amount is None and spc is None


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


def test_stake_nullifier_tree_stream_rebuilds_each_snapshot(voted, monkeypatch):
    """What a wallet does to vote: page the tree by leaf index, take the first
    nf_size - 1 values, insert them in order; the root is the snapshot's."""
    store, _ = voted
    monkeypatch.setattr(config, "INDEX_DB", store.path)
    app = FastAPI()
    app.include_router(privacy_router.router)
    c = ChainClient(TestClient(app))
    want = summary(scenario(VOTE_SCENARIO))
    rows, i = [], 1
    while True:
        r = c.get("/privacy/stake/nullifier-tree", params={"from_index": i, "limit": 1})
        body = r.json()
        assert body["fields"] == ["index", "nullifier", "height"]
        assert ("immutable" in r.headers["cache-control"]) == body["complete"]
        assert body["size"] == len(want["nf_index"]) + 1
        rows += body["nullifiers"]
        i = body["next_index"]
        if not body["complete"]:
            break
    assert [tuple(x) for x in rows] == want["nf_index"]
    assert c.get("/privacy/status").json()["stake_nf_tree_size"] == len(rows) + 1
    snaps = c.get("/privacy/stake/snapshots").json()
    assert snaps["fields"] == ["height", "proposal_id", "root", "tree_size", "nf_root", "nf_size"]
    assert len(snaps["snapshots"]) == len(want["snapshots"])
    for _, _, _, _, nf_root, nf_size in snaps["snapshots"]:
        t = IndexedTree()
        for _, nf, _ in rows[:max(nf_size - 1, 0)]:
            t.insert(int(nf, 16))
        assert t.size == nf_size
        assert t.root().to_bytes(32, "big").hex() == nf_root
    # Height-paged stream unchanged, now in leaf order within a height.
    body = c.get("/privacy/stake/nullifiers").json()
    assert [nf for _, nfs in body["blocks"] for nf in nfs] == [nf for _, nf, _ in rows]


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
    body = c.get("/privacy/stake/nullifier-tree").json()
    assert (body["nullifiers"], body["size"], body["next_index"]) == ([], 0, 1)
    assert c.get("/privacy/stake/snapshots").json()["snapshots"] == []
    assert c.get("/privacy/roots/latest").json()["stake"] is None


def test_an_index_from_before_the_nullifier_tree_is_refused(tmp_path):
    import sqlite3

    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE stake_nullifiers (seq INTEGER PRIMARY KEY, nf BLOB NOT NULL UNIQUE, height INTEGER NOT NULL)")
    old.commit()
    old.close()
    with pytest.raises(RuntimeError, match="wipe INDEX_DB"):
        Store(path)
