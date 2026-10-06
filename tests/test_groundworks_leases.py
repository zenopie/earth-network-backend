"""Groundworks split leases: the positions table, {base}/stake/positions and
the lapse events.

TestRecordGroundworksLease (bin/chainrec's own scenario, every write in a
block, at the shortest lease of one day): position 0 locked with a split,
renewed with MsgUpdatePosition halfway, standing past its first lease end and
lapsing at its renewed one (shieldedstaking_position split_lapsed, BeginBlock);
then the operator's MsgSetAllocations vote lapsing (x/allocation
split_lapsed). TestGroundworksPositions (the chain's): lock, an update that
clears the split, unlock. Each recorded block carries the keeper's positions
after it. Refusals are synthetic, in the chain's event shape.
"""
import asyncio
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy as privacy_router
from services.privacy import events
from services.privacy.indexer import Indexer
from services.privacy.rpc import parse_time
from services.privacy.store import Inconsistent, Store, connect
from tests.privacy_fixtures import SCENARIOS, ChainClient, FakeRPC, load

LEASE = "TestRecordGroundworksLease"
POSITIONS = "TestGroundworksPositions"
VAL = "earthvaloper1v"


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())


def _open(store: Store) -> list[dict]:
    rows = store.conn.execute("SELECT id, validator, split_expires_at FROM positions"
                              " WHERE closed_height IS NULL ORDER BY id").fetchall()
    return [{"id": i, "validator": v, "split_expires_at": e} for i, v, e in rows]


@pytest.mark.parametrize("name", [n for n in SCENARIOS if "positions" in load(n)["blocks"][0]])
def test_positions_match_the_keeper_after_every_block(tmp_path, name):
    sc = load(name)
    store = Store(str(tmp_path / "p.db"))
    for b in sc["blocks"]:
        sync(Indexer(store, FakeRPC(sc, tip=b["height"]), batch=3))
        assert store.last_height() == b["height"]
        assert _open(store) == b["positions"], b["height"]


def test_the_lease_scenario_renews_then_lapses(tmp_path):
    sc = load(LEASE)
    store = Store(str(tmp_path / "p.db"))
    sync(Indexer(store, FakeRPC(sc), batch=4))
    by_h = {b["height"]: b for b in sc["blocks"]}
    deltas = {h: events.parse_block(h, parse_time(b["time"]), b["hash"], b["block_results"]) for h, b in by_h.items()}
    changes = [(h, p.action, p.id, p.split_expires_at) for h, d in sorted(deltas.items()) for p in d.positions]
    assert [c[1] for c in changes] == ["lock", "update", "split_lapsed"]
    (lock_h, _, _, first), (upd_h, _, _, renewed), (lapse_h, _, _, after) = changes
    day = 86400
    assert first == parse_time(by_h[lock_h]["time"]) + day
    assert renewed == parse_time(by_h[upd_h]["time"]) + day and renewed > first, "the same split again renews it"
    assert after == 0 and parse_time(by_h[lapse_h]["time"]) >= renewed
    # Between the first lease end and the lapse the renewed split stood.
    assert any(first < parse_time(b["time"]) < renewed for b in sc["blocks"])
    row = store.conn.execute("SELECT id, validator, split_expires_at, height, updated_height, closed_height"
                             " FROM positions").fetchall()
    assert row == [(0, by_h[lock_h]["positions"][0]["validator"], 0, lock_h, lapse_h, None)]
    # The operator's vote lapsed after it, checked and not stored.
    lapses = [(h, s) for h, d in sorted(deltas.items()) for s in d.split_lapses]
    assert len(lapses) == 1
    h, s = lapses[0]
    assert h > lapse_h and s.stream == "STREAM_ID_GROUNDWORKS" and s.voter.startswith("earth1")
    assert 0 < s.expires_at <= parse_time(by_h[h]["time"])


def test_an_unlocked_position_keeps_its_row(tmp_path):
    sc = load(POSITIONS)
    store = Store(str(tmp_path / "p.db"))
    sync(Indexer(store, FakeRPC(sc), batch=4))
    (i, exp, h, upd, closed), = store.conn.execute(
        "SELECT id, split_expires_at, height, updated_height, closed_height FROM positions").fetchall()
    assert (i, exp) == (0, 0) and h < upd == closed == sc["blocks"][-1]["height"]


# --- {base}/stake/positions -----------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (1, 2, 100, 1000))
    path = str(tmp_path / "api.db")
    store = Store(path)
    sync(Indexer(store, FakeRPC(load(LEASE)), batch=4))
    # Two more positions, one of them closed, so paging has rows to walk.
    t = int(store.meta("last_time"))
    h = store.last_height()
    store.apply(events.BlockDelta(height=h + 1, time=t + 5, hash="X1", positions=[
        events.PositionChange(1, "lock", VAL, t + 5 + 86400), events.PositionChange(2, "lock", VAL, 0)]))
    store.apply(events.BlockDelta(height=h + 2, time=t + 10, hash="X2", positions=[
        events.PositionChange(2, "unlock", VAL, 0)]))
    monkeypatch.setattr(config, "INDEX_DB", path)
    app = FastAPI()
    app.include_router(privacy_router.router)
    return ChainClient(TestClient(app)), store, t, h


def test_positions_stream_serves_every_lease(client):
    c, store, t, h = client
    for limit in (1, 2, 100):
        rows, i = [], 0
        while True:
            r = c.get("/privacy/stake/positions", params={"from_index": i, "limit": limit})
            assert r.status_code == 200, r.text
            assert r.headers["cache-control"] == "public, max-age=2", "rows change in place: never immutable"
            body = r.json()
            assert body["format"] == 1 and body["size"] == 3
            assert body["fields"] == ["id", "validator", "split_expires_at", "height", "updated_height", "closed_height"]
            rows += body["rows"]
            i = body["next_index"]
            if not body["complete"]:
                break
        assert [r[0] for r in rows] == [0, 1, 2]
        assert rows[1][1:] == [VAL, t + 5 + 86400, h + 1, h + 1, None]
        assert rows[2][2:] == [0, h + 1, h + 2, h + 2]
    assert c.get("/privacy/status").json()["positions"] == 3


@pytest.mark.parametrize("params", [{"from_index": 1, "limit": 2}, {"limit": 5}])
def test_positions_paging_follows_the_rules(client, params):
    r = client[0].get("/privacy/stake/positions", params=params)
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store"


# --- refusals ---------------------------------------------------------------------

def _ev(type_, **attrs):
    return {"type": type_, "attributes": [{"key": k, "value": str(v)} for k, v in attrs.items()]}


def _pos(action, pid=0, exp=0, val=VAL):
    return _ev("shieldedstaking_position", action=action, position_id=pid, validator=val, derth=1, weight=1,
               split_expires_at=exp)


def _parse(evs, time=1000):
    return events.parse_block(5, time, "H", {"height": "5", "txs_results": [{"code": 0, "events": evs}]})


@pytest.mark.parametrize("ev, match", [
    (_pos("vote"), "action"),
    (_ev("shieldedstaking_position", action="lock", position_id=0, validator=VAL), "no split_expires_at"),
    (_pos("lock", val=""), "no validator"),
    (_pos("split_lapsed", exp=2000), "split_lapsed with a lease end"),
    (_pos("lock", exp=1000), "not after the block"),
    (_pos("update", exp=-1), "negative"),
    (_ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=1001), "block at 1000"),
    (_ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=0), "expires_at 0"),
    (_ev("split_lapsed", stream="", voter="earth1x", expires_at=10), "no stream"),
])
def test_malformed_lease_events_are_refused(ev, match):
    with pytest.raises(events.EventError, match=match):
        _parse([ev])


def test_well_formed_lease_events_parse():
    d = _parse([_pos("lock", 0, 2000), _pos("update", 0, 0), _pos("unlock", 0, 0),
                _ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=1000)])
    assert [(p.action, p.split_expires_at) for p in d.positions] == [("lock", 2000), ("update", 0), ("unlock", 0)]
    assert d.split_lapses == [events.SplitLapse("STREAM_ID_GROUNDWORKS", "earth1x", 1000)]


def _apply(store, height, time, *changes):
    store.apply(events.BlockDelta(height=height, time=time, hash=f"H{height}", positions=list(changes)))


@pytest.mark.parametrize("second, match", [
    (events.PositionChange(2, "lock", VAL, 0), "locked, expected id 1"),
    (events.PositionChange(0, "lock", VAL, 0), "locked, expected id 1"),
    (events.PositionChange(1, "update", VAL, 0), "not an open position"),
    (events.PositionChange(0, "update", "earthvaloper1w", 0), "indexed at earthvaloper1v"),
    (events.PositionChange(0, "split_lapsed", VAL, 0), "lease ends at 5000"),
])
def test_position_changes_that_contradict_the_index_halt(tmp_path, second, match):
    store = Store(str(tmp_path / "r.db"))
    _apply(store, 1, 100, events.PositionChange(0, "lock", VAL, 5000))
    with pytest.raises(Inconsistent, match=match):
        _apply(store, 2, 200, second)
    assert store.last_height() == 1


def test_a_closed_position_takes_no_more_changes(tmp_path):
    store = Store(str(tmp_path / "r.db"))
    _apply(store, 1, 100, events.PositionChange(0, "lock", VAL, 0))
    _apply(store, 2, 200, events.PositionChange(0, "unlock", VAL, 0))
    with pytest.raises(Inconsistent, match="not an open position"):
        _apply(store, 3, 300, events.PositionChange(0, "update", VAL, 9000))


def test_a_lapse_at_or_after_the_lease_end_is_applied(tmp_path):
    store = Store(str(tmp_path / "r.db"))
    _apply(store, 1, 100, events.PositionChange(0, "lock", VAL, 5000))
    # A lease that failed to retire is re-queued a day later: still a lapse.
    _apply(store, 2, 5000 + 86400, events.PositionChange(0, "split_lapsed", VAL, 0))
    assert store.conn.execute("SELECT split_expires_at, updated_height FROM positions").fetchone() == (0, 2)


def test_starting_past_the_first_lock_halts(tmp_path):
    store = Store(str(tmp_path / "r.db"))
    with pytest.raises(Inconsistent, match="history before the start height is missing"):
        _apply(store, 7, 100, events.PositionChange(3, "lock", VAL, 0))


def test_an_index_from_before_the_positions_table_is_refused(tmp_path):
    path = str(tmp_path / "old.db")
    Store(path).apply(events.BlockDelta(height=1, time=1, hash="H1"))
    raw = sqlite3.connect(path)
    raw.execute("DROP TABLE positions")
    raw.commit()
    raw.close()
    with pytest.raises(RuntimeError, match="no positions table"):
        connect(path)
