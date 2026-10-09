"""Groundworks leases as the indexer sees them: the operator split lapse
events and the lease alerts. Groundworks votes themselves (chain v1.2.0,
by stake note) are not indexed: wallets read the chain's whole list.

TestRecordGroundworksLease (bin/chainrec's own scenario, recorded before
v1.2.0 retired positions): its shieldedstaking_position events are history
the indexer passes over; the operator's MsgSetAllocations vote lapsing
(x/allocation split_lapsed) is checked. Refusals are synthetic, in the
chain's event shape.
"""
import asyncio
import sqlite3

import pytest

from services.privacy import events
from services.privacy.indexer import Indexer
from services.privacy.rpc import parse_time
from services.privacy.store import Store, connect
from tests.privacy_fixtures import FakeRPC, load

LEASE = "TestRecordGroundworksLease"
VAL = "earthvaloper1v"


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())


def test_the_lease_scenario_indexes_and_the_operator_vote_lapses(tmp_path):
    sc = load(LEASE)
    store = Store(str(tmp_path / "p.db"))
    sync(Indexer(store, FakeRPC(sc), batch=4))
    assert store.last_height() == sc["blocks"][-1]["height"]
    by_h = {b["height"]: b for b in sc["blocks"]}
    deltas = {h: events.parse_block(h, parse_time(b["time"]), b["hash"], b["block_results"]) for h, b in by_h.items()}
    lapses = [(h, s) for h, d in sorted(deltas.items()) for s in d.split_lapses]
    assert len(lapses) == 1
    h, s = lapses[0]
    assert s.stream == "STREAM_ID_GROUNDWORKS" and s.voter.startswith("earth1")
    assert 0 < s.expires_at <= parse_time(by_h[h]["time"])


def _ev(type_, **attrs):
    return {"type": type_, "attributes": [{"key": k, "value": str(v)} for k, v in attrs.items()]}


def _parse(evs, time=1000):
    return events.parse_block(5, time, "H", {"height": "5", "txs_results": [{"code": 0, "events": evs}]})


def test_retired_position_events_are_passed_over():
    # Before v1.2.0: a position's events, malformed or not, change nothing.
    d = _parse([_ev("shieldedstaking_position", action="lock", position_id=0, validator=VAL, split_expires_at=2000),
                _ev("shieldedstaking_position", action="vote")])
    assert d.split_lapses == [] and d.lease_alerts == []


@pytest.mark.parametrize("ev, match", [
    (_ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=1001), "block at 1000"),
    (_ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=0), "expires_at 0"),
    (_ev("split_lapsed", stream="", voter="earth1x", expires_at=10), "no stream"),
])
def test_malformed_lease_events_are_refused(ev, match):
    with pytest.raises(events.EventError, match=match):
        _parse([ev])


def test_well_formed_lease_events_parse():
    d = _parse([_ev("split_lapsed", stream="STREAM_ID_GROUNDWORKS", voter="earth1x", expires_at=1000)])
    assert d.split_lapses == [events.SplitLapse("STREAM_ID_GROUNDWORKS", "earth1x", 1000)]


def test_lease_alerts_are_kept_for_the_log_and_never_halt(caplog):
    OPER = "earthvaloper1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"
    # x/allocation's alert events (chain 7033eac), with the BeginBlock mode
    # the sweep emits them under, and one missing every attribute: none is
    # checked, none changes the delta's state.
    begin = {"key": "mode", "value": "BeginBlock"}
    alerts = [
        _ev("lease_retire_failed", stream="STREAM_ID_GROUNDWORKS", lapser="groundworks_votes", key=VAL,
            expires_at=900, retry_at=900 + 86400, error=f"boom: validator {OPER} not found"),
        _ev("lease_settle_held", stream="STREAM_ID_GROUNDWORKS", expires_at=990),
        _ev("lease_backlog_drained", stream="STREAM_ID_GROUNDWORKS", lapse_seconds=1501),
        _ev("lease_settle_held"),
    ]
    for a in alerts:
        a["attributes"].append(begin)
    d = events.parse_block(5, 1000, "H", {"height": "5", "finalize_block_events": alerts})
    assert [k for k, _ in d.lease_alerts] == ["lease_retire_failed", "lease_settle_held", "lease_backlog_drained",
                                             "lease_settle_held"]
    assert d.split_lapses == []

    from services.privacy import indexer
    caplog.set_level("INFO", logger=indexer.logger.name)
    indexer._log_lease_alerts(5, d.lease_alerts)
    levels = [(r.levelname, r.getMessage().split(": ", 1)[1].split()[0]) for r in caplog.records]
    assert levels == [("ERROR", "lease_retire_failed"), ("ERROR", "lease_settle_held"),
                      ("INFO", "lease_backlog_drained"), ("ERROR", "lease_settle_held")]
    assert "retry_at=87300" in caplog.records[0].getMessage() and "lapser=groundworks_votes" in caplog.records[0].getMessage()
    # NO_LOGS policy 2: no address, neither the event's key nor one in its error.
    assert "<addr>" in caplog.records[0].getMessage()
    assert all(OPER not in r.getMessage() and VAL not in r.getMessage() and "key=" not in r.getMessage()
               for r in caplog.records)


def test_an_index_with_the_retired_positions_table_still_opens(tmp_path):
    path = str(tmp_path / "old.db")
    Store(path).apply(events.BlockDelta(height=1, time=1, hash="H1"))
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE positions (id INTEGER PRIMARY KEY, validator TEXT NOT NULL, split_expires_at INTEGER NOT NULL,"
                " height INTEGER NOT NULL, updated_height INTEGER NOT NULL, closed_height INTEGER)")
    raw.commit()
    raw.close()
    connect(path).close()
