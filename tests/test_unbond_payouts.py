"""Undelegation payouts (chain 48b631c, ORCHARD_DESIGN section 18.1): the chain
mints an undelegation's value x payout / requested to the msg's pc, with the
msg's ciphertext, as pool notes (MintNoteSplit, 2^63-1 a note), then emits
shieldedstaking_unbond_payout. No claim, no unbond/ stake note. Also the
four-slot stake vote's event (section 18.2), which the index does not read."""
import asyncio
import base64
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy
from services.privacy import events
from services.privacy.indexer import Halted, Indexer
from services.privacy.store import Store
from tests.privacy_fixtures import ChainClient, FakeRPC, load, seed_chain
from tests.stake_fixtures import VOTE_SCENARIO, summary

LIFECYCLE = "TestPrivateStakingLifecycle"
MANY_NOTES = "TestStakeVoteManyNotesOneWeight"
U63 = 2**63 - 1
CT = bytes(range(177))
CT2 = bytes([7]) * 177


def _ev(t: str, mode: str | None = "EndBlock", **attrs) -> dict:
    a = [{"key": k, "value": str(v)} for k, v in attrs.items()]
    if mode:
        a.append({"key": "mode", "value": mode})
    return {"type": t, "attributes": a}


def _mint(pos: int, value: int, ct: bytes = CT, module: str = "shieldedstaking", denom: str = "uerth") -> list[dict]:
    b64 = base64.b64encode(ct).decode()
    return [_ev("shielded_note", position=pos, commitment=(1000 + pos).to_bytes(32, "big").hex(), ciphertext=b64),
            _ev("shielded_mint", module=module, amount=f"{value}{denom}", position=pos, ciphertext=b64)]


def _payout(pid: int, positions: list[int], amount: int, **over) -> dict:
    a = {"payout_id": pid, "validator": "earthvaloper1x", "epoch": 3, "value": amount, "amount": amount,
         "notes": len(positions), "positions": ",".join(map(str, positions)), **over}
    return _ev("shieldedstaking_unbond_payout", **a)


def _split(pid: int, first: int, values: list[int], ct: bytes = CT) -> list[dict]:
    """A payout's EndBlock events: its mints, then its payout event."""
    ps = list(range(first, first + len(values)))
    return [e for p, v in zip(ps, values) for e in _mint(p, v, ct)] + [_payout(pid, ps, sum(values))]


def _block(height: int, finalize: list[dict]) -> dict:
    return {"height": str(height), "txs_results": [], "finalize_block_events": finalize}


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
    idx = Indexer(store, FakeRPC(sc))

    async def go():
        await idx.prepare()
        while await idx.step():
            pass

    asyncio.run(go())


def _index(path: str, name: str) -> None:
    store = Store(path)
    _sync(store, load(name))
    store.close()


def _client(monkeypatch, path: str) -> ChainClient:
    monkeypatch.setattr(config, "INDEX_DB", path)
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (100, 1000))
    app = FastAPI()
    app.include_router(privacy.router)
    return ChainClient(TestClient(app))


def _rows(c: ChainClient) -> list[dict]:
    body = c.get("/privacy/notes", params={"from_pos": 0, "limit": 1000}).json()
    assert body["format"] == 2
    return [dict(zip(body["fields"], r)) for r in body["notes"]]


# --- the recorded lifecycle -------------------------------------------------

def test_the_recorded_undelegation_is_paid_as_a_note_in_the_stream(tmp_path, monkeypatch):
    sc = load(LIFECYCLE)
    [(uh, un)] = _events(sc, "shieldedstaking_undelegate")
    assert {"epoch", "payout_id"} <= un.keys() and "denom" not in un
    [(mh, mat)] = _events(sc, "shieldedstaking_matured")
    assert (mat["validator"], mat["epoch"]) == (un["validator"], un["epoch"]) and "denom" not in mat
    [(ph, pay)] = _events(sc, "shieldedstaking_unbond_payout")
    assert (pay["payout_id"], pay["validator"], pay["epoch"], pay["value"]) == \
        (un["payout_id"], un["validator"], un["epoch"], un["value"])
    assert ph > mh > uh, "paid in a block after the maturity block"
    assert not _events(sc, "shieldedstaking_claim")
    assert all(a["denom"].startswith("derth/") for _, a in summary(sc)["notes"] if "denom" in a)

    path = str(tmp_path / "i.db")
    _index(path, LIFECYCLE)
    rows = {r["position"]: r for r in _rows(_client(monkeypatch, path))}
    positions = [int(p) for p in pay["positions"].split(",")]
    assert len(positions) == int(pay["notes"]) == 1
    row = rows[positions[0]]
    assert row["height"] == ph and row["amount"] == f"{pay['amount']}uerth"
    assert len(base64.b64decode(row["ciphertext"])) == 177
    assert row["owner_pk"] is row["rho"] is row["rcm"] is None


def test_a_recorded_payout_naming_another_note_halts(tmp_path):
    sc = copy.deepcopy(load(LIFECYCLE))
    for b in sc["blocks"]:
        for e in b["block_results"].get("finalize_block_events") or []:
            if e["type"] == "shieldedstaking_unbond_payout":
                a = next(a for a in e["attributes"] if a["key"] == "positions")
                a["value"] = "0"
    with pytest.raises(Halted, match="names position 0, not a shieldedstaking mint"):
        _sync(Store(str(tmp_path / "i.db")), sc)


# --- split payouts ----------------------------------------------------------

def test_a_split_payout_is_every_note_with_one_ciphertext():
    values = [U63, U63, 12]
    d = events.parse_block(9, 0, "H", _block(9, _split(4, 0, values)))
    assert [(n.position, n.amount, n.ciphertext) for n in d.notes] == [
        (0, f"{U63}uerth", CT), (1, f"{U63}uerth", CT), (2, "12uerth", CT)]
    assert [(p.payout_id, p.amount, p.positions) for p in d.payouts] == [(4, 2 * U63 + 12, [0, 1, 2])]


def test_two_payouts_in_one_block_and_a_payout_of_nothing():
    fin = [*_split(1, 0, [5]), *_split(2, 1, [U63, 1], ct=CT2), _payout(3, [], 0)]
    d = events.parse_block(9, 0, "H", _block(9, fin))
    assert [(p.payout_id, p.positions) for p in d.payouts] == [(1, [0]), (2, [1, 2]), (3, [])]


def test_split_payouts_in_the_stream(tmp_path, monkeypatch):
    path = str(tmp_path / "i.db")
    seed_chain(path)
    st = Store(path)
    assert st.apply(events.parse_block(1, 1, "H1", _block(1, [*_split(7, 0, [U63, U63, 3]),
                                                             *_split(8, 3, [40], ct=CT2)])))
    st.close()
    rows = _rows(_client(monkeypatch, path))
    assert [(r["position"], r["amount"], base64.b64decode(r["ciphertext"])) for r in rows] == [
        (0, f"{U63}uerth", CT), (1, f"{U63}uerth", CT), (2, "3uerth", CT), (3, "40uerth", CT2)]
    assert all(r["height"] == 1 and r["owner_pk"] is None for r in rows)


@pytest.mark.parametrize("fin,match", [
    # A position that is no mint of this block.
    ([*_mint(0, 5), _payout(1, [0, 1], 10)], "names position 1"),
    # Another module's mint (an LP payout is not an undelegation's).
    ([*_mint(0, 5, module="dex"), _payout(1, [0], 5)], "not a shieldedstaking mint"),
    # The notes do not add up to the amount.
    ([*_mint(0, 5), *_mint(1, 5), _payout(1, [0, 1], 11)], "amount 11, its notes hold 10"),
    # A split payout's notes carry one ciphertext.
    ([*_mint(0, 5), *_mint(1, 5, ct=CT2), _payout(1, [0, 1], 10)], "ciphertexts differ"),
    # Not uerth.
    ([*_mint(0, 5, denom="uanml"), _payout(1, [0], 5)], "not uerth"),
    # notes and positions disagree.
    ([*_mint(0, 5), _payout(1, [0], 5, notes=2)], "notes 2, 1 positions"),
    ([*_mint(0, 5), _payout(1, [0, 0], 10)], "a position twice"),
    ([_payout(1, [], 5)], "amount 5 in 0 notes"),
    # One note claimed by two payouts.
    ([*_mint(0, 5), _payout(1, [0], 5), _payout(2, [0], 5)], "another payout's"),
])
def test_a_payout_that_does_not_match_its_mints_is_refused(fin, match):
    with pytest.raises(events.EventError, match=match):
        events.parse_block(9, 0, "H", _block(9, fin))


def test_a_failed_payout_changes_nothing():
    fail = _ev("shieldedstaking_unbond_payout_failed", payout_id=4, validator="earthvaloper1x", epoch=3,
               attempts=1, retry_at=3600, error="uerth: send disabled")
    d = events.parse_block(9, 0, "H", _block(9, [fail]))
    assert d.notes == [] and d.payouts == []


# --- two-slot stake votes (four slots at 48b631c) ------------------------------

def test_a_two_note_vote_lists_its_used_slots_only():
    """The event's vote_nullifiers are the used slots (1..2 since chain
    dff3a9b), not the msg's two with zeros: a one-note vote lists one."""
    counts = {len(a["vote_nullifiers"].split(","))
              for name in (MANY_NOTES, VOTE_SCENARIO) for _, a in _events(load(name), "shieldedstaking_stake_vote")
              if "vote_nullifiers" in a}
    assert {1, 2} == counts


@pytest.mark.parametrize("name", [MANY_NOTES, VOTE_SCENARIO])
def test_vote_nullifiers_are_not_in_the_stake_nullifier_tree(tmp_path, name):
    """vote_nullifiers (comma-separated hex) spend nothing: the stake
    nullifier tree holds the stake nullifier events only."""
    sc = load(name)
    votes = _events(sc, "shieldedstaking_stake_vote")
    assert votes and all("vote_nullifier" not in a for _, a in votes)
    vnfs = [v for _, a in votes if "vote_nullifiers" in a for v in a["vote_nullifiers"].split(",")]
    assert vnfs and all(len(bytes.fromhex(v)) == 32 and int(v, 16) for v in vnfs)
    store = Store(str(tmp_path / "i.db"))
    _sync(store, sc)
    nfs = {r[0].hex() for r in store.conn.execute("SELECT nf FROM stake_nullifiers")}
    assert nfs == {nf for _, nf in summary(sc)["nullifiers"]}
    assert not nfs & set(vnfs)
