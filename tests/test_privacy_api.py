"""The /privacy streams, served from an index of recorded chain blocks."""
import asyncio
import base64
import tracemalloc

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy
from services.privacy.indexer import Indexer
from services.privacy.store import Store
from tests.privacy_fixtures import BASE, ChainClient, FakeRPC, load, seed_chain, set_meta


def _index(path: str, name: str, tip: int | None = None) -> None:
    store = Store(path)
    idx = Indexer(store, FakeRPC(load(name), tip=tip))

    async def go():
        await idx.prepare()
        while await idx.step():
            pass

    asyncio.run(go())
    store.close()


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    """The recorded scenarios are small: page sizes small enough to page them."""
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (1, 2, 4, 7, 100, 1000))


@pytest.fixture
def api(tmp_path, monkeypatch):
    path = str(tmp_path / "index.db")
    monkeypatch.setattr(config, "INDEX_DB", path)
    _index(path, "TestPrivatePersonhood")
    app = FastAPI()
    app.include_router(privacy.router)
    return ChainClient(TestClient(app))


def test_status(api):
    s = api.get("/privacy/status").json()
    sc = load("TestPrivatePersonhood")
    assert s["chain_id"] == sc["chain_id"]
    assert s["synced_height"] == sc["blocks"][-1]["height"]
    assert s["notes"] == sc["blocks"][-1]["note_tree_size"]
    assert s["identity_leaves"] == sc["blocks"][-1]["identity_tree_size"]
    assert s["halted"] is None


def test_notes_pages_cover_everything_once_and_full_pages_are_immutable(api):
    total = api.get("/privacy/status").json()["notes"]
    seen, pos = [], 0
    while True:
        r = api.get("/privacy/notes", params={"from_pos": pos, "limit": 7})
        body = r.json()
        if body["complete"]:
            assert "immutable" in r.headers["cache-control"]
        else:
            assert "immutable" not in r.headers["cache-control"]
        seen += body["notes"]
        if not body["complete"]:
            break
        pos = body["next_pos"]
        assert pos % 7 == 0, "a full page's next_pos is the next aligned cursor"
    assert [n[0] for n in seen] == list(range(total))
    pos_, height, cm, ct, amount, owner_pk, rho, rcm = seen[0]
    assert len(bytes.fromhex(cm)) == 32
    base64.b64decode(ct, validate=True)
    assert owner_pk is rho is rcm is None
    assert body["format"] == 2
    assert body["fields"] == ["position", "height", "cm", "ciphertext", "amount", "owner_pk", "rho", "rcm"]


def test_referral_mint_rows_carry_their_opening_and_match_locally(api):
    # Notes format 2: the referral note the chain mints to a
    # handle's address has no ciphertext; its row carries owner_pk, rho, rcm.
    # A wallet that knows its owner_pk matches the row from the row alone:
    # cm == H(TAG_CM, AssetID(denom), amount, PC(owner_pk, rho, rcm)).
    from services.zk import privacy as zp
    assert api.get("/privacy/status").json()["note_format"] == 2
    body = api.get("/privacy/notes", params={"limit": 1000}).json()
    assert body["format"] == 2
    rows = [dict(zip(body["fields"], r)) for r in body["notes"]]
    open_rows = [r for r in rows if r["owner_pk"] is not None]
    assert len(open_rows) == 2  # C2 and D1 name "amy"
    for r in open_rows:
        assert r["ciphertext"] is None
        assert r["rho"] and r["rcm"] and r["amount"].endswith("uerth")
        value = int(r["amount"][:-len("uerth")])
        pc_ = zp.pc(*(int(r[k], 16) for k in ("owner_pk", "rho", "rcm")))
        assert zp.cm(zp.asset_id("uerth"), value, pc_) == int(r["cm"], 16)
    # Both pay amy, so both rows name the same owner_pk, with distinct openings.
    assert open_rows[0]["owner_pk"] == open_rows[1]["owner_pk"]
    assert open_rows[0]["rho"] != open_rows[1]["rho"]
    # Every other row: a ciphertext, no opening.
    for r in rows:
        if r["owner_pk"] is None:
            assert r["ciphertext"] and r["rho"] is None and r["rcm"] is None


def test_nullifier_pages_never_split_a_height(api):
    all_rows = api.get("/privacy/nullifiers", params={"limit": 1000}).json()
    flat_all = [(h, nf) for h, nfs in all_rows["blocks"] for nf in nfs]
    assert len(flat_all) == api.get("/privacy/status").json()["nullifiers"]
    got, h = [], 0
    while True:
        r = api.get("/privacy/nullifiers", params={"from_height": h, "limit": 4})
        body = r.json()
        heights = [b[0] for b in body["blocks"]]
        assert len(heights) == len(set(heights))
        got += [(bh, nf) for bh, nfs in body["blocks"] for nf in nfs]
        if not body["complete"]:
            assert "immutable" not in r.headers["cache-control"]
            break
        assert "immutable" in r.headers["cache-control"]
        h = body["next_height"]
    assert got == flat_all
    assert body["next_height"] == body["synced_height"] + 1


def test_a_height_larger_than_the_limit_comes_whole(api):
    first = api.get("/privacy/nullifiers", params={"limit": 1000}).json()["blocks"]
    big = max(first, key=lambda b: len(b[1]))
    assert len(big[1]) >= 2
    body = api.get("/privacy/nullifiers", params={"from_height": big[0], "limit": 1}).json()
    assert body["blocks"][0] == big and body["next_height"] == big[0] + 1


def test_identity_leaves_and_zeroings(api):
    body = api.get("/privacy/identity").json()
    assert body["size"] == len(body["leaves"])
    assert body["fields"] == ["index", "height", "leaf", "zeroed_height", "time"]
    from services.privacy.rpc import parse_time
    times = {b["height"]: parse_time(b["time"]) for b in load("TestPrivatePersonhood")["blocks"]}
    for l in body["leaves"]:
        assert l[4] == times[l[1]], "time is the block time of the leaf's height"
    zeroed = [l for l in body["leaves"] if l[3] is not None]
    assert zeroed, "the scenario zeroes leaves"
    z = api.get("/privacy/identity/zeroed").json()
    indexes = sorted(i for _, idxs in z["blocks"] for i in idxs)
    assert indexes == sorted(l[0] for l in zeroed)
    for h, idxs in z["blocks"]:
        for i in idxs:
            assert body["leaves"][i][3] == h


def test_roots_latest_matches_the_chain(api):
    sc = load("TestPrivatePersonhood")
    last = sc["blocks"][-1]
    r = api.get("/privacy/roots/latest")
    body = r.json()
    assert body["note"]["root"] == last["note_latest_root"]
    assert body["note"]["tree_size"] == last["note_tree_size"]
    assert body["identity"]["root"] == last["identity_latest_root"]
    assert r.headers["cache-control"] == "public, max-age=2"


def test_rates(tmp_path, monkeypatch):
    path = str(tmp_path / "staking.db")
    monkeypatch.setattr(config, "INDEX_DB", path)
    _index(path, "TestPrivateStakingLifecycle")
    app = FastAPI()
    app.include_router(privacy.router)
    c = ChainClient(TestClient(app))
    latest = c.get("/privacy/rates").json()
    assert latest["rates"] and latest["latest_epoch"] is not None
    v, rate, supply, epoch, height = latest["rates"][0]
    assert v.startswith("earthvaloper") and epoch == latest["latest_epoch"]
    first = c.get("/privacy/rates", params={"epoch": 1})
    assert first.json()["rates"]
    assert first.headers["cache-control"] == "public, max-age=86400"


def test_limits_are_validated(api, monkeypatch):
    monkeypatch.setattr(config, "PRIVACY_PAGE_MAX", 4)
    assert len(api.get("/privacy/notes", params={"limit": 4}).json()["notes"]) == 4
    r = api.get("/privacy/notes", params={"limit": 7})
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store", "past PRIVACY_PAGE_MAX"
    assert api.get("/privacy/notes", params={"from_pos": -1}).status_code == 422
    assert api.get("/privacy/notes", params={"limit": 0}).status_code == 422


def test_empty_index_serves_empty_streams(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INDEX_DB", str(tmp_path / "empty.db"))
    seed_chain(config.INDEX_DB)
    app = FastAPI()
    app.include_router(privacy.router)
    c = ChainClient(TestClient(app))
    assert c.get("/privacy/status").json()["synced_height"] == 0
    assert c.get("/privacy/notes").json()["notes"] == []
    assert c.get("/privacy/roots/latest").json()["note"] is None


def test_no_per_user_lookups():
    app = FastAPI()
    app.include_router(privacy.router)
    paths = set(app.openapi()["paths"])
    base = "/privacy/{chain_id}/{genesis}"
    assert paths == {"/privacy/status"} | {base + p for p in (
        "/status", "/notes", "/nullifiers", "/identity", "/identity/zeroed", "/roots/latest", "/rates",
        "/stake/notes", "/stake/nullifiers", "/stake/nullifier-tree", "/stake/roots", "/stake/snapshots",
        "/handles",  # the whole directory; no path names one handle
        "/debt_rows",  # every slash debt row; no path names one move
    )}


def test_streams_live_under_the_chain_and_its_genesis(api):
    s = api.get("/privacy/status").json()
    sc = load("TestPrivatePersonhood")
    first = min(sc["blocks"], key=lambda b: b["height"])
    assert s["genesis_hash"] == first["hash"].lower()
    assert s["genesis"] == first["hash"].lower()[:16]
    assert s["base"] == f"/privacy/{sc['chain_id']}/{s['genesis']}"
    assert api.client.get(s["base"] + "/status").json()["base"] == s["base"]
    assert api.client.get(s["base"] + "/notes").status_code == 200


@pytest.mark.parametrize("path", [
    "/privacy/notes",                                   # unkeyed: gone
    "/privacy/earth-shielded-test/0000000000000000/notes",  # an earlier chain, same id
    "/privacy/earth-1/{genesis}/notes",                 # another chain id
])
def test_another_chain_is_404_and_never_cached(api, path):
    g = api.get("/privacy/status").json()["genesis"]
    r = api.client.get(path.format(genesis=g))
    assert r.status_code == 404
    if path != "/privacy/notes":
        assert r.headers["cache-control"] == "no-store"


def test_an_index_that_never_met_its_chain_serves_no_streams(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INDEX_DB", str(tmp_path / "new.db"))
    app = FastAPI()
    app.include_router(privacy.router)
    c = TestClient(app)
    s = c.get("/privacy/status").json()
    assert s["base"] is None and s["genesis"] is None
    assert c.get("/privacy/None/None/notes").status_code == 404


@pytest.mark.parametrize("path,param", [
    ("/privacy/notes", "from_pos"), ("/privacy/nullifiers", "from_height"),
    ("/privacy/identity", "from_index"), ("/privacy/identity/zeroed", "from_height"),
    ("/privacy/rates", "epoch"), ("/privacy/stake/notes", "from_pos"),
    ("/privacy/stake/nullifiers", "from_height"), ("/privacy/stake/roots", "from_height"),
    ("/privacy/stake/nullifier-tree", "from_index"), ("/privacy/stake/snapshots", "from_height"),
    ("/privacy/notes", "limit"),
])
def test_integers_past_int64_are_422_not_500(api, path, param):
    """2^64 must be a 422, not an OverflowError at SQLite's bind (a 500; audit 3)."""
    assert api.get(path, params={param: str(2**64)}).status_code == 422
    assert api.get(path, params={param: str(2**63)}).status_code == 422
    top = 2**63 - 1
    if param == "limit":
        assert api.get(path, params={param: str(top)}).status_code == 400, "not a page size"
    elif param in ("from_pos", "from_index"):
        # Cursors are page-aligned (audit-4 B3): the last aligned page is fine.
        assert api.get(path, params={param: str(top)}).status_code == 400
        assert api.get(path, params={param: str(top - top % 1000)}).status_code == 200
    else:
        assert api.get(path, params={param: str(top)}).status_code == 200


def _racing(monkeypatch, path, table_sql_marker):
    """A reader connection on which the indexer commits block 4 right after
    the page's row query (audit 3)."""
    from services.privacy import store as store_mod
    from services.privacy.events import BlockDelta, StakeNullifier

    w = store_mod.Store(path)
    w.set_meta("chain_id", "earth-test")
    w.set_meta("genesis_hash", "ab" * 32)
    w.apply(BlockDelta(1, 1000, "H1"))
    w.apply(BlockDelta(2, 1001, "H2", nullifiers=[b"\x01" * 32], stake_nullifiers=[StakeNullifier(b"\x11" * 32, 1)]))
    w.apply(BlockDelta(3, 1002, "H3"))
    inner = store_mod.connect(path, readonly=True)

    class RacingConn:
        fired = False

        def execute(self, sql, *a):
            cur = inner.execute(sql, *a)
            if not RacingConn.fired and table_sql_marker in sql:
                RacingConn.fired = True
                w.apply(BlockDelta(4, 1003, "H4", nullifiers=[b"\x04" * 32], stake_nullifiers=[StakeNullifier(b"\x14" * 32, 2)]))
            return cur

    monkeypatch.setattr(privacy, "_db", lambda: RacingConn())
    return RacingConn


@pytest.mark.parametrize("route,marker,key", [
    ("nullifiers", "FROM nullifiers", "blocks"),
    ("stake/nullifiers", "FROM stake_nullifiers", "blocks"),
])
def test_a_page_and_its_synced_height_are_one_snapshot(tmp_path, monkeypatch, route, marker, key):
    path = str(tmp_path / "race.db")
    monkeypatch.setattr(config, "INDEX_DB", path)
    racing = _racing(monkeypatch, path, marker)
    app = FastAPI()
    app.include_router(privacy.router)
    c = TestClient(app)
    body = c.get(f"/privacy/earth-test/{'ab' * 8}/{route}", params={"from_height": 0}).json()
    assert racing.fired
    heights = [h for h, _ in body[key]]
    assert heights == [2]
    # The page saw heights up to 3; block 4 committed after its first read.
    assert body["synced_height"] == 3 and body["next_height"] == 4
    nxt = c.get(f"/privacy/earth-test/{'ab' * 8}/{route}", params={"from_height": body["next_height"]}).json()
    assert [h for h, _ in nxt[key]] == [4], "following next_height reaches block 4's rows"


def test_only_aligned_pages_of_fixed_sizes(notes_index):
    get = notes_index.get
    for params in ({"from_pos": 1}, {"from_pos": 999}, {"from_pos": 100, "limit": 1000},
                   {"from_pos": 0, "limit": 5000}, {"from_pos": 0, "limit": 999}):
        r = get(BASE + "/notes", params=params)
        assert r.status_code == 400, params
        assert r.headers["cache-control"] == "no-store"
    r = get(BASE + "/notes", params={"from_pos": 1000})
    body = r.json()
    assert [n[0] for n in body["notes"]] == list(range(1000, 2000))
    assert body["complete"] and body["next_pos"] == 2000 and "immutable" in r.headers["cache-control"]
    tip = get(BASE + "/notes", params={"from_pos": 5000}).json()
    assert [n[0] for n in tip["notes"]] == list(range(5000, 5500)) and not tip["complete"]
    assert tip["next_pos"] == 5500, "where the data ends; the wallet asks for page 5000 again later"
    r = get(BASE + "/notes", params={"from_pos": 200, "limit": 100})
    assert [n[0] for n in r.json()["notes"]] == list(range(200, 300))


def test_a_max_page_is_bounded(notes_index):
    tracemalloc.start()
    r = notes_index.get(BASE + "/notes", params={"from_pos": 0, "limit": config.PRIVACY_PAGE_MAX},
                        headers={"accept-encoding": "gzip"})
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r.status_code == 200 and len(r.json()["notes"]) == 1000
    assert peak < 4 * 2**20, f"peak heap {peak / 2**20:.1f} MiB for one max page"


def test_a_halted_index_serves_no_stream(notes_index):
    set_meta(halted="block 9: note at position 3, expected 0")
    for path in ("/notes?from_pos=1000", "/status", "/roots/latest", "/handles"):
        r = notes_index.get(BASE + path)
        assert r.status_code == 503 and r.headers["cache-control"] == "no-store", path
    s = notes_index.get("/privacy/status")
    assert s.status_code == 200 and "expected 0" in s.json()["halted"]


def test_a_page_is_immutable_only_once_its_heights_are_verified(notes_index):
    set_meta(verified_height="0")  # the rows are at height 1
    r = notes_index.get(f"{BASE}/notes?from_pos=1000")
    assert r.status_code == 200 and r.json()["complete"]
    assert r.headers["cache-control"] == "public, max-age=2"
    set_meta(verified_height="1")
    assert "immutable" in notes_index.get(f"{BASE}/notes?from_pos=1000").headers["cache-control"]
