"""Stake vintages (chain v1.3.0, ORCHARD_DESIGN.md 8.9) as the indexer sees
them.

The denom and month rules (services/privacy/vintages) against the chain's Go
(zk_vectors.json, bin/zkvectors). Then the recorded scenarios:
TestRecordStakeVintages (bin/chainrec: a base-vintage delegation, a check-in
to the next month, a restake naming its month, the old vintage's retirement
with its Groundworks vote swept, the retired note's withdrawal on its
unsuffixed asset and its payout at maturity) and the chain's
TestCheckInProof, indexed whole with real proofs. Refusals are synthetic,
in the chain's event shape.
"""
import asyncio
import base64
import calendar
import json
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy as privacy_router
from services.privacy import events, vintages
from services.privacy.indexer import Indexer
from services.privacy.rpc import parse_time
from services.privacy.store import Store
from services.zk import privacy
from tests.privacy_fixtures import ChainClient, FakeRPC, load
from tests.stake_fixtures import summary

VEC = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "privacy", "zk_vectors.json")))["vintages"]
SCENARIO = "TestRecordStakeVintages"
CHECK_IN = "TestCheckInProof"
VAL = "earthvaloper1v"
# 2027-02-01T01:00:00Z: month 202702.
FEB = calendar.timegm((2027, 2, 1, 1, 0, 0))


def hx(v: int) -> str:
    return privacy.field_bytes(v).hex()


# --- the rules, against the chain's Go ---------------------------------------

def test_denoms_match_go():
    for valoper, m, base, want in VEC["denoms"]:
        assert vintages.denom(valoper, m, base) == want


def test_parse_matches_go():
    for d, valoper, month, ok in VEC["parse"]:
        got = vintages.parse_denom(d)
        assert (got is not None) == ok, d
        if ok:
            assert got == (valoper, month), d
    # Round trip: the base vintage parses as month 0, any other as itself.
    for valoper, m, base, d in VEC["denoms"]:
        assert vintages.parse_denom(d) == (valoper, 0 if m == base else m)


def test_months_match_go():
    assert vintages.LIVE_VINTAGE_MONTHS == VEC["live_months"]
    for ts, month, start, retires, oldest in VEC["months"]:
        assert vintages.month_of(ts) == month
        assert vintages.start(month) == start
        assert vintages.retires_at(month) == retires
        assert vintages.oldest_live(month) == oldest
    for m, cur, live, retired in VEC["live"]:
        assert (vintages.is_live(m, cur), vintages.is_retired(m, cur)) == (live, retired), (m, cur)


def test_vintaged_asset_and_stake_commitment_match_go():
    assert hx(privacy.asset_id(VEC["asset"]["denom"])) == VEC["asset"]["id"]
    d = VEC["stake_cm"]
    spc = privacy.stake_pc(privacy.owner_pk(42), 7, 9)
    assert hx(privacy.stake_cm(privacy.asset_id(d["denom"]), int(d["amount"]), spc)) == d["cm"]
    # The base vintage's unsuffixed denom is another asset than its
    # suffixed spelling (which the chain never supplies).
    v = VEC["denoms"][0]
    assert privacy.asset_id(v[3]) != privacy.asset_id(f"{v[3]}/{v[2]:06d}")


@pytest.mark.parametrize("m", [0, 199912, 202600, 202613, 1000001])
def test_not_vintages(m):
    assert not vintages.is_vintage(m)


# --- the recorded scenarios -------------------------------------------------------

def _events(sc: dict, typ: str) -> list[tuple[int, dict]]:
    out = []
    for b in sc["blocks"]:
        r = b["block_results"]
        for e in [e for tx in r.get("txs_results") or [] for e in tx.get("events") or []] + \
                (r.get("finalize_block_events") or []):
            if e["type"] == typ:
                out.append((b["height"], {a["key"]: a["value"] for a in e["attributes"]}))
    return out


def _sync(store: Store, sc: dict) -> None:
    idx = Indexer(store, FakeRPC(sc), batch=4)

    async def go():
        await idx.prepare()
        while await idx.step():
            pass

    asyncio.run(go())


def _deltas(sc: dict) -> dict[int, events.BlockDelta]:
    return {b["height"]: events.parse_block(b["height"], parse_time(b["time"]), b["hash"], b["block_results"])
            for b in sc["blocks"]}


@pytest.mark.parametrize("name", [SCENARIO, CHECK_IN])
def test_the_recorded_vintage_scenarios_index_whole(tmp_path, name):
    sc = load(name)
    store = Store(str(tmp_path / "v.db"))
    _sync(store, sc)
    assert store.last_height() == sc["blocks"][-1]["height"]
    want = summary(sc)
    c = store.conn
    assert c.execute("SELECT COUNT(*) FROM stake_notes").fetchone()[0] == len(want["notes"])
    assert c.execute("SELECT COUNT(*) FROM stake_nullifiers").fetchone()[0] == len(want["nullifiers"])
    store.close()


def test_the_recorded_check_in(tmp_path):
    sc = load(SCENARIO)
    deltas = _deltas(sc)
    [(h, ci)] = [(h, c) for h, d in deltas.items() for c in d.check_ins]
    assert ci.to_vintage == vintages.month_of(deltas[h].time)
    assert ci.from_vintage == vintages.add_months(ci.to_vintage, -1) and ci.derth > 0
    # Its stake proof is a two-lane one, as a redelegation's: two notes and
    # every lane's non-zero nullifiers, in the same block; no move.
    assert len(deltas[h].stake_notes) == 2 and len(deltas[h].stake_nullifiers) >= 2
    assert not _events(sc, "shieldedstaking_redelegate")
    # The chain's own real-proof test emits the same.
    [(h2, a)] = _events(load(CHECK_IN), "shieldedstaking_check_in")
    assert (a["from_vintage"], a["to_vintage"]) == (str(ci.from_vintage), str(ci.to_vintage))


def test_the_recorded_retirement_withdrawal_and_payout(tmp_path, monkeypatch):
    sc = load(SCENARIO)
    deltas = _deltas(sc)
    [(dh, dl)] = _events(sc, "shieldedstaking_delegate")
    jan = int(dl["vintage"])
    assert jan == vintages.month_of(deltas[dh].time)

    [(rh, r)] = [(h, r) for h, d in deltas.items() for r in d.vintage_retired]
    assert r.vintage == jan and r.supply > 0 and r.value > 0
    assert deltas[rh].time >= vintages.retires_at(jan) > deltas[rh - 1].time
    # Its Groundworks vote was swept in the same block, as "retired".
    swept = [a for h, a in _events(sc, "shieldedstaking_groundworks_vote") if a["action"] == "retired"]
    assert [(a["vintage"], a["split_expires_at"]) for a in swept] == [(str(jan), "0")]
    assert all(a["split_expires_at"] == "0" for _, a in _events(sc, "shieldedstaking_groundworks_vote"))
    # The held payout is never paid as such.
    assert all(int(a["payout_id"]) != r.payout_id for _, a in _events(sc, "shieldedstaking_unbond_payout"))

    [(wh, w)] = [(h, w) for h, d in deltas.items() for w in d.retired_withdrawals]
    assert (w.validator, w.vintage, w.derth, w.value) == (r.validator, jan, r.supply, r.value)
    assert (w.remaining_supply, w.remaining_value) == (0, 0), "the whole vintage withdrawn"
    assert not [a for h, a in _events(sc, "shieldedstaking_undelegate") if h == wh], "instead of an undelegate"
    [(ph, pay)] = _events(sc, "shieldedstaking_unbond_payout")
    assert int(pay["payout_id"]) == w.payout_id and ph > wh

    # The payout is an ordinary minted row of /notes.
    path = str(tmp_path / "v.db")
    store = Store(path)
    _sync(store, sc)
    store.close()
    monkeypatch.setattr(config, "INDEX_DB", path)
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (100, 1000))
    app = FastAPI()
    app.include_router(privacy_router.router)
    c = ChainClient(TestClient(app))
    body = c.get("/privacy/notes", params={"from_pos": 0, "limit": 1000}).json()
    rows = {r[0]: dict(zip(body["fields"], r)) for r in body["notes"]}
    row = rows[int(pay["positions"])]
    assert row["height"] == ph and row["amount"] == f"{pay['amount']}uerth"
    assert len(base64.b64decode(row["ciphertext"])) == 177


def test_the_recorded_restake_names_its_month():
    # The February note was restaked with its month in the msg (a non-zero
    # vintage): the chain took the proof, so the restake's block has a stake
    # note and nullifiers like any; the stream does not tell vintages apart.
    sc = load(SCENARIO)
    deltas = _deltas(sc)
    ch = next(h for h, d in deltas.items() if d.check_ins)
    after = [h for h, d in sorted(deltas.items()) if h > ch and d.stake_notes]
    assert len(after) >= 3, "the restake, the vote and the withdrawal"


# --- refusals --------------------------------------------------------------------

def _ev(type_, **attrs):
    return {"type": type_, "attributes": [{"key": k, "value": str(v)} for k, v in attrs.items()]}


def _parse(evs, time=FEB):
    return events.parse_block(5, time, "H", {"height": "5", "txs_results": [{"code": 0, "events": evs}]})


RETIRED = vintages.add_months(202702, -13)  # 202601: retired at 2027-02-01
LIVE_OLD = vintages.add_months(202702, -12)  # 202602: the oldest live


def test_well_formed_vintage_events_parse():
    d = _parse([
        _ev("shieldedstaking_check_in", validator=VAL, from_vintage=LIVE_OLD, to_vintage=202702, derth=5),
        _ev("shieldedstaking_vintage_retired", validator=VAL, vintage=RETIRED, supply=10, value=11, epoch=3, payout_id=0),
        _ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=RETIRED, derth=4, value=0, epoch=3, payout_id=0,
            remaining_supply=6, remaining_value=11),
        _ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=RETIRED, derth=6, value=11, epoch=3, payout_id=1,
            remaining_supply=0, remaining_value=0),
        _ev("shieldedstaking_delegate", validator=VAL, vintage=202702),
        _ev("shieldedstaking_undelegate", validator=VAL, vintage=LIVE_OLD),
        _ev("shieldedstaking_groundworks_vote", action="cast", vintage=LIVE_OLD, split_expires_at=0),
        _ev("shieldedstaking_groundworks_vote", action="retired", vintage=RETIRED, split_expires_at=0),
        # A spend of a retired note cancels its vote: not checked.
        _ev("shieldedstaking_groundworks_vote", action="cancelled", vintage=RETIRED, split_expires_at=0),
    ])
    assert d.check_ins == [events.CheckIn(VAL, LIVE_OLD, 202702, 5)]
    assert d.vintage_retired == [events.VintageRetired(VAL, RETIRED, 10, 11, 0)]
    assert [w.remaining_supply for w in d.retired_withdrawals] == [6, 0]


def test_events_from_before_vintages_parse():
    # v1.2.x: no vintage on a stake msg's events, leased Groundworks votes.
    d = _parse([
        _ev("shieldedstaking_delegate", validator=VAL, derth=5),
        _ev("shieldedstaking_undelegate", validator=VAL, derth=5, epoch=1, payout_id=0),
        _ev("shieldedstaking_groundworks_vote", action="cast", split_expires_at=FEB + 86400),
        _ev("shieldedstaking_groundworks_vote", action="lapsed", split_expires_at=FEB - 1),
    ])
    assert d.check_ins == d.vintage_retired == d.retired_withdrawals == []


@pytest.mark.parametrize("ev, match", [
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=LIVE_OLD, to_vintage=202703, derth=5), "block's month"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=202702, to_vintage=202702, derth=5), "not a live month before"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=RETIRED, to_vintage=202702, derth=5), "not a live month before"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=202703, to_vintage=202702, derth=5), "not a live month before"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=LIVE_OLD, to_vintage=202702, derth=0), "no derth"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=0, to_vintage=202702, derth=1), "not a vintage"),
    (_ev("shieldedstaking_check_in", validator=VAL, from_vintage=202613, to_vintage=202702, derth=1), "not a vintage"),
    (_ev("shieldedstaking_check_in", from_vintage=LIVE_OLD, to_vintage=202702, derth=1), "no validator"),
    (_ev("shieldedstaking_vintage_retired", validator=VAL, vintage=LIVE_OLD, supply=1, value=1, epoch=1, payout_id=0),
     "has not retired"),
    (_ev("shieldedstaking_vintage_retired", validator=VAL, vintage=RETIRED, supply=0, value=0, epoch=1, payout_id=0),
     "no supply"),
    (_ev("shieldedstaking_vintage_retired", validator=VAL, vintage=RETIRED, supply=1, value=-1, epoch=1, payout_id=0),
     "negative"),
    (_ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=LIVE_OLD, derth=1, value=1, epoch=1, payout_id=0,
         remaining_supply=0, remaining_value=0), "has not retired"),
    (_ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=RETIRED, derth=0, value=0, epoch=1, payout_id=0,
         remaining_supply=1, remaining_value=1), "no derth"),
    (_ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=RETIRED, derth=1, value=1, epoch=1, payout_id=0,
         remaining_supply=0, remaining_value=3), "nothing left"),
    (_ev("shieldedstaking_retired_withdrawal", validator=VAL, vintage=RETIRED, derth=1, value=1, epoch=1, payout_id=0,
         remaining_supply=0), "remaining_value"),
    (_ev("shieldedstaking_delegate", validator=VAL, vintage=LIVE_OLD), "block's month"),
    (_ev("shieldedstaking_undelegate", validator=VAL, vintage=RETIRED), "not live"),
    (_ev("shieldedstaking_undelegate", validator=VAL, vintage=202703), "not live"),
    (_ev("shieldedstaking_undelegate", validator=VAL, vintage=0), "not a vintage"),
    (_ev("shieldedstaking_redelegate", src_validator=VAL, dst_validator="earthvaloper1w", credited=1, move_time=1,
         move_key="11" * 32, vintage=LIVE_OLD, dst_vintage=LIVE_OLD), "dst_vintage"),
    (_ev("shieldedstaking_redelegate", src_validator=VAL, dst_validator="earthvaloper1w", credited=1, move_time=1,
         move_key="11" * 32, vintage=RETIRED, dst_vintage=202702), "not live"),
    (_ev("shieldedstaking_groundworks_vote", action="cast", vintage=RETIRED, split_expires_at=0), "not live"),
    (_ev("shieldedstaking_groundworks_vote", action="cast", vintage=202702, split_expires_at=FEB + 86400), "no lease"),
    (_ev("shieldedstaking_groundworks_vote", action="retired", vintage=LIVE_OLD, split_expires_at=0), "has not retired"),
])
def test_malformed_vintage_events_are_refused(ev, match):
    with pytest.raises(events.EventError, match=match):
        _parse([ev])


def test_a_recorded_check_in_moved_to_another_month_halts(tmp_path):
    # The block's month decides: the same events a month later are refused.
    sc = load(SCENARIO)
    b = next(b for b in sc["blocks"] if any(e["type"] == "shieldedstaking_check_in"
                                             for tx in b["block_results"].get("txs_results") or []
                                             for e in tx.get("events") or []))
    t = parse_time(b["time"])
    events.parse_block(b["height"], t, b["hash"], b["block_results"])
    with pytest.raises(events.EventError, match="block's month"):
        events.parse_block(b["height"], vintages.start(vintages.add_months(vintages.month_of(t), 1)), b["hash"],
                           b["block_results"])
