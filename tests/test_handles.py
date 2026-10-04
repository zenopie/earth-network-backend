"""The handle directory stream ({base}/handles), from the chain's Handles query.

Shapes are pinned to the chain: zk_vectors.json "handles_query" is a
QueryHandlesRequest / QueryHandlesResponse the chain's own types marshalled
(bin/zkvectors), and every recorded block of TestPrivatePersonhood carries
the chain query server's answer at that block (bin/chainrec, pages of one),
which the indexer reads through FakeRPC exactly as it reads a node.
"""
import asyncio
import json
import logging
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy
from services.privacy import handles
from services.privacy.indexer import Indexer
from services.privacy.rpc import proto_fields
from services.privacy.store import Store
from tests.privacy_fixtures import ChainClient, FakeRPC, load

VEC = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "privacy", "zk_vectors.json")))["handles_query"]
SCENARIO = "TestPrivatePersonhood"


def recorded(block: dict) -> list[handles.Entry]:
    """The directory the chain answered at a recorded block, every page joined."""
    out = []
    for page in block["handles"]:
        out += handles.parse_page(bytes.fromhex(page))[0]
    return out


def as_rows(entries) -> list[list]:
    return [[e.handle, e.address, e.status, e.expires_at, e.renewal_until, e.owner] for e in entries]


# --- wire shape, against the chain's own types ------------------------------

def test_request_encoding_matches_the_chain():
    assert handles.request(VEC["request_start"], VEC["request_limit"]).hex() == VEC["request"]
    assert handles.request("", 0) == b""


def test_response_decoding_matches_the_chain():
    entries, nxt = handles.parse_page(bytes.fromhex(VEC["response"]))
    assert nxt == VEC["next"]
    # The chain's JSON leaves an empty owner out (a handle never claimed).
    assert [e.__dict__ for e in entries] == [{"owner": "", **v} for v in VEC["entries"]]
    assert entries[0].owner == "" and len(entries[2].owner) == 64
    assert {e.status for e in entries} == set(handles.STATUSES)
    assert handles.next_change(entries) == 1700000000 + 2592000  # bob's renewal_until < zed-99's expires_at


def test_every_recorded_page_is_well_formed():
    for b in load(SCENARIO)["blocks"]:
        recorded(b)  # raises Malformed otherwise


def test_recorded_owners_are_the_handle_events_owners():
    """Every claimed handle in the chain's directory names, as owner, the
    owner its latest handle_bound / handle_moved event carried (chain audit
    round 6); handle_moved's previous_owner is the owner before it."""
    from services.privacy.events import ordered_events

    owners, seen = {}, 0
    for b in load(SCENARIO)["blocks"]:
        for ev in ordered_events(b["block_results"]):
            if ev["type"] not in handles.EVENTS:
                continue
            a = {x["key"]: x["value"] for x in ev["attributes"]}
            assert len(a["owner"]) == 64 and a["owner"] == a["owner"].lower()
            if ev["type"] == "handle_moved":
                assert a["previous_owner"] == owners[a["handle"]] != a["owner"]
            if ev["type"] == "handle_released":
                owners.pop(a["handle"], None)
            else:
                owners[a["handle"]] = a["owner"]
        for e in recorded(b):
            if e.owner:
                assert e.owner == owners[e.handle], (b["height"], e.handle)
                seen += 1
    assert seen


@pytest.mark.parametrize("bad", [
    {"handle": "Bob"}, {"handle": "-ab"}, {"handle": "ab"}, {"handle": "a" * 33},
    {"status": "expired"}, {"address": "earth1abcdefgh"}, {"address": ""},
    {"expires_at": -1}, {"renewal_until": 1699999999},
    {"owner": "ab" * 31}, {"owner": "ab" * 33}, {"owner": "AB" * 32}, {"owner": "0x" + "ab" * 31},
    {"owner": "g" * 64}, {"owner": " " + "a" * 63},
])
def test_a_malformed_entry_is_refused(bad):
    good = dict(VEC["entries"][1])
    good.update(bad)
    with pytest.raises(handles.Malformed):
        handles.parse_entry(_raw_entry(good))


@pytest.mark.parametrize("owner", ["", "0f" * 32])
def test_owner_is_64_lowercase_hex_or_none(owner):
    e = handles.parse_entry(_raw_entry(dict(VEC["entries"][1], owner=owner)))
    assert e.owner == owner


def _raw_entry(e: dict) -> bytes:
    return (_s(1, e["handle"]) + _s(2, e["address"]) + _s(3, e["status"])
            + _v(4, e["expires_at"]) + _v(5, e["renewal_until"]) + (_s(6, e["owner"]) if e.get("owner") else b""))


def _varint(v: int) -> bytes:
    v &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _s(num, s):
    b = s.encode()
    return _varint(num << 3 | 2) + _varint(len(b)) + b


def _v(num, v):
    return _varint(num << 3) + _varint(v)


def _page(entries: list[bytes], nxt: str = "") -> bytes:
    out = b"".join(_varint(1 << 3 | 2) + _varint(len(e)) + e for e in entries)
    return out + (_s(2, nxt) if nxt else b"")


def _entry(handle: str, status="live", expires=2_000_000_000, until=2_002_592_000) -> bytes:
    return (_s(1, handle) + _s(2, VEC["address"]) + _s(3, status) + _v(4, expires) + _v(5, until))


class _Pages:
    def __init__(self, pages: dict[str, bytes]):
        self.pages, self.asked = pages, []

    async def abci_query(self, path, data=b"", height=None):
        assert path == handles.HANDLES_QUERY
        start = (proto_fields(data).get(1) or [b""])[-1].decode()
        self.asked.append((start, height))
        return self.pages[start]


def test_fetch_follows_next_at_one_height():
    rpc = _Pages({"": _page([_entry("amy"), _entry("bob")], "bob"), "bob": _page([_entry("cat")])})
    got = asyncio.run(handles.fetch(rpc, 77, limit=2))
    assert [e.handle for e in got] == ["amy", "bob", "cat"]
    assert rpc.asked == [("", 77), ("bob", 77)]


@pytest.mark.parametrize("pages", [
    {"": _page([_entry("bob"), _entry("amy")])},                      # out of order
    {"": _page([_entry("amy"), _entry("amy")])},                      # twice
    {"": _page([_entry("amy")], "bob")},                              # next is not the last handle
    {"": _page([], "amy")},                                           # next on an empty page
    {"": _page([_entry("amy")], "amy"), "amy": _page([_entry("aaa")])},  # goes backwards
])
def test_fetch_refuses_a_directory_out_of_shape(pages):
    with pytest.raises(handles.Malformed):
        asyncio.run(handles.fetch(_Pages(pages), 5))


def test_fetch_is_bounded():
    rpc = _Pages({"": _page([_entry("amy"), _entry("bob")], "bob"), "bob": _page([_entry("cat")])})
    with pytest.raises(handles.Malformed):
        asyncio.run(handles.fetch(rpc, 5, max_entries=2))


# --- the indexer keeps a snapshot of the chain's directory ------------------

def _follow(path: str, upto: int | None = None, rpc: FakeRPC | None = None, **kw) -> tuple[Store, FakeRPC, list]:
    """Indexes the scenario one block at a time (caught up after each, as a
    live indexer is), recording the snapshot after each block."""
    sc = load(SCENARIO)
    rpc = rpc or FakeRPC(sc, tip=sc["blocks"][0]["height"])
    store = Store(path)
    idx = Indexer(store, rpc, **kw)
    snaps = []

    async def go():
        await idx.prepare()
        for b in sc["blocks"]:
            if upto is not None and b["height"] > upto:
                break
            rpc.tip = b["height"]
            await idx.step()
            rows = store.conn.execute("SELECT handle, address, status, expires_at, renewal_until, owner"
                                      " FROM handles ORDER BY idx").fetchall()
            snaps.append((b, store.meta("handles_height"), [list(r) for r in rows]))

    asyncio.run(go())
    return store, rpc, snaps


def test_the_snapshot_is_the_chains_directory_after_every_block(tmp_path):
    store, rpc, snaps = _follow(str(tmp_path / "i.db"))
    changed = 0
    for b, height, rows in snaps:
        want = as_rows(recorded(b))
        if int(height) == b["height"]:
            assert rows == want, b["height"]
            changed += 1
        else:
            # Not re-read: nothing changed it since the snapshot's block.
            assert rows == want, (b["height"], height)
    # Bound "alice", moved it, renewed it, changed it to "amy", changed the
    # address, and the change to "amy-2" with D1 taking "amy" in one block.
    final = as_rows(recorded(snaps[-1][0]))
    assert [r[0] for r in final] == ["amy", "amy-2"] and {r[2] for r in final} == {"live"}
    assert changed < len(snaps), "re-read only when due, not every block"
    store.close()


def test_reread_after_a_handle_event_and_not_otherwise(tmp_path):
    # The scenario jumps days at a time: a max age past its span isolates
    # the event trigger.
    store, rpc, snaps = _follow(str(tmp_path / "i.db"), handles_max_age=10**9)
    reads = sorted({int(c.split()[-1]) for c in rpc.calls if c.startswith(f"abci_query {handles.HANDLES_QUERY}")})
    sc = load(SCENARIO)
    event_heights = {b["height"] for b in sc["blocks"]
                     if any(e["type"] in handles.EVENTS for tx in b["block_results"].get("txs_results") or []
                            for e in tx.get("events") or [])
                     or any(e["type"] in handles.EVENTS for e in b["block_results"].get("finalize_block_events") or [])}
    assert event_heights, "the scenario binds handles"
    first = sc["blocks"][0]["height"]
    # The first snapshot, then one after each block with a handle event
    # (no status in this scenario lapses by time).
    assert set(reads) == {first} | event_heights
    store.close()


def test_a_status_change_by_time_alone_is_due(tmp_path):
    store = Store(str(tmp_path / "i.db"))
    store.set_meta("last_height", "10")
    store.set_meta("last_time", "1000")
    entries = [handles.Entry("amy", VEC["address"], "live", 1500, 1600)]
    store.replace_handles(10, 1000, entries, handles.next_change(entries))
    assert not store.handles_due(3600)
    store.set_meta("last_height", "11")
    store.set_meta("last_time", "1499")
    assert not store.handles_due(3600)
    store.set_meta("last_time", "1500")  # amy's lease ends: live -> renewal
    assert store.handles_due(3600)
    store.set_meta("last_time", "1200")
    assert not store.handles_due(3600)
    assert store.handles_due(100), "older than the max age"
    store.set_meta("handles_changed_height", "11")
    assert store.handles_due(3600), "a handle event after the snapshot"
    store.close()


def test_a_malformed_answer_keeps_the_last_snapshot_and_the_trees_go_on(tmp_path, caplog):
    sc = load(SCENARIO)
    rpc = FakeRPC(sc, tip=sc["blocks"][0]["height"])
    good = rpc.abci_query

    async def lying(path, data=b"", height=None):
        if path == handles.HANDLES_QUERY and height >= 25:
            return _page([_entry("Mallory")])
        return await good(path, data, height)

    rpc.abci_query = lying
    caplog.set_level(logging.WARNING)
    store, _, snaps = _follow(str(tmp_path / "i.db"), rpc=rpc)
    assert store.meta("halted") is None
    assert store.last_height() == sc["blocks"][-1]["height"]
    assert int(store.meta("handles_height")) < 25
    assert [r[0] for r in snaps[-1][2]] == ["alice"]
    assert "handle directory at" in caplog.text
    store.close()


def test_a_chain_without_the_query_indexes_the_trees(tmp_path):
    sc = load(SCENARIO)
    for b in sc["blocks"]:
        b.pop("handles")
    store, _, snaps = _follow(str(tmp_path / "i.db"), rpc=FakeRPC(sc, tip=sc["blocks"][0]["height"]))
    assert store.meta("halted") is None and store.meta("handles_height") is None
    store.close()


# --- the stream -------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    path = str(tmp_path / "index.db")
    monkeypatch.setattr(config, "INDEX_DB", path)
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (1, 2, 100, 1000))
    _follow(path)[0].close()
    app = FastAPI()
    app.include_router(privacy.router)
    return ChainClient(TestClient(app))


def test_stream_serves_the_whole_directory_in_aligned_pages(api):
    sc = load(SCENARIO)
    want = as_rows(recorded(sc["blocks"][-1]))
    got, i = [], 0
    while True:
        r = api.get("/privacy/handles", params={"from_index": i, "limit": 1})
        assert r.status_code == 200
        assert r.headers["cache-control"] == privacy.TIP
        body = r.json()
        assert body["fields"] == ["handle", "address", "status", "expires_at", "renewal_until", "owner"]
        assert body["size"] == len(want)
        assert body["height"] <= body["synced_height"] == sc["blocks"][-1]["height"]
        got += body["handles"]
        i = body["next_index"]
        if body["last_page"]:
            break
    assert got == want
    whole = api.get("/privacy/handles").json()
    assert whole["handles"] == want and whole["last_page"]
    assert api.get("/privacy/status").json()["handles"] == len(want)


def test_snapshot_time_is_its_blocks_time(api):
    from services.privacy.rpc import parse_time

    sc = load(SCENARIO)
    body = api.get("/privacy/handles").json()
    block = next(b for b in sc["blocks"] if b["height"] == body["height"])
    assert body["time"] == parse_time(block["time"])
    assert body["synced_height"] >= body["height"]


@pytest.mark.parametrize("params", [{"from_index": 1, "limit": 2}, {"limit": 3}, {"limit": 5000}])
def test_stream_takes_only_aligned_pages_of_fixed_sizes(api, params):
    r = api.get("/privacy/handles", params=params)
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store"


def test_no_lookup_of_one_handle(api):
    base = api.base
    for path in ("/handles/amy", "/handle/amy", "/handles?handle=amy"):
        r = api.client.get(base + path)
        if r.status_code == 200:
            # A query parameter the stream does not take is ignored: the
            # answer is the whole first page, the same for every handle.
            assert r.json()["handles"] == api.get("/privacy/handles").json()["handles"]
        else:
            assert r.status_code == 404


def test_empty_before_the_first_snapshot(tmp_path, monkeypatch):
    from tests.privacy_fixtures import seed_chain

    path = str(tmp_path / "e.db")
    seed_chain(path)
    monkeypatch.setattr(config, "INDEX_DB", path)
    app = FastAPI()
    app.include_router(privacy.router)
    c = ChainClient(TestClient(app))
    body = c.get("/privacy/handles").json()
    assert (body["height"], body["size"], body["handles"], body["last_page"]) == (None, 0, [], True)


def test_a_directory_from_before_owner_is_read_again(tmp_path):
    """An index whose handles table predates HandleEntry.owner (chain audit
    round 6) drops the snapshot (not history) and takes a new one."""
    import sqlite3

    path = str(tmp_path / "i.db")
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE handles (idx INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
                              status TEXT NOT NULL, expires_at INTEGER NOT NULL, renewal_until INTEGER NOT NULL);
        CREATE TABLE handles_staging (idx INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
                              status TEXT NOT NULL, expires_at INTEGER NOT NULL, renewal_until INTEGER NOT NULL);
        INSERT INTO handles VALUES (0, 'amy', 'erthz1x', 'live', 1, 2);
        INSERT INTO meta VALUES ('handles_height', '7'), ('handles_time', '9'), ('handles_size', '1'),
                                ('last_height', '7'), ('chain_id', 'earth-test');
    """)
    c.commit()
    c.close()
    store = Store(path)
    assert "owner" in [r[1] for r in store.conn.execute("PRAGMA table_info(handles)")]
    assert store.conn.execute("SELECT COUNT(*) FROM handles").fetchone() == (0,)
    assert store.meta("handles_height") is None and store.meta("handles_size") is None
    assert store.meta("last_height") == "7" and store.meta("chain_id") == "earth-test"
    assert store.handles_due(3600)
    store.close()
