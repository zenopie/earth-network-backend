"""The slash debt tree ({base}/debt_rows) and the stake notes private redelegations make.

TestRecordRedelegateSlashDebt (bin/chainrec's own scenario, every write in a
block): a first delegation (a padding spend), two private redelegations A ->
B after an infraction of A, the evidence (two shieldedstaking_debt_row
events, their move_slashed and one slash_debt), a labelled top-up, the label
cleared and the note undelegated. The rewritten row (a second slash of a
move) and every refusal are synthetic, in the chain's event shape.
"""
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
from services.privacy.rpc import proto_fields
from services.privacy.store import Inconsistent, Store
from services.zk import debt
from tests.privacy_fixtures import ChainClient, FakeRPC, seed_chain
from tests.stake_fixtures import DEBT_SCENARIO, scenario

EMPTY = debt.EMPTY_ROOT.to_bytes(32, "big").hex()


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())


def _attrs(e: dict) -> dict:
    return {a["key"]: a["value"] for a in e.get("attributes") or []}


def _txs(sc: dict):
    """(height, tx index, [events]) of every tx."""
    for b in sc["blocks"]:
        for i, tx in enumerate(b["block_results"].get("txs_results") or []):
            yield b["height"], i, tx.get("events") or []


def _finalize(sc: dict, type_: str):
    for b in sc["blocks"]:
        for e in b["block_results"].get("finalize_block_events") or []:
            if e["type"] == type_:
                yield b["height"], _attrs(e)


@pytest.fixture
def indexed(tmp_path):
    store = Store(str(tmp_path / "d.db"))
    rpc = FakeRPC(scenario(DEBT_SCENARIO))
    sync(Indexer(store, rpc, batch=5))
    return store, rpc


# --- the recorded scenario -----------------------------------------------------

def test_debt_rows_are_indexed_as_the_chain_wrote_them(indexed):
    store, rpc = indexed
    sc = scenario(DEBT_SCENARIO)
    want = list(_finalize(sc, "shieldedstaking_debt_row"))
    assert len(want) == 2, "two moves slashed"
    rows = store.conn.execute("SELECT idx, key, retained, height, updated_height FROM debt_rows ORDER BY idx").fetchall()
    assert [(i, k.hex(), r, h, u) for i, k, r, h, u in rows] == [
        (int(a["index"]), a["move_key"], int(a["retained"]), h, h) for h, a in want]
    writes = store.conn.execute("SELECT idx, key, retained, height, root FROM debt_writes ORDER BY seq").fetchall()
    assert [(i, k.hex(), r, h, root.hex()) for i, k, r, h, root in writes] == [
        (int(a["index"]), a["move_key"], int(a["retained"]), h, a["root"]) for h, a in want]
    last = sc["blocks"][-1]
    assert store.debt_size() == last["debt_tree_size"] == 3
    assert store.debt_root()[0].hex() == last["debt_current_root"]
    # The window and clear_before the indexer read from Query/DebtTree at its
    # last check (the last block: batches end at the tip).
    q = proto_fields(bytes.fromhex(last["debt_tree"]))
    assert int(store.meta("debt_window_seconds")) == q[4][-1] == 1815000  # 21 days + 600 s
    assert int(store.meta("debt_clear_before")) == q[5][-1] == last_time(last) - 1815000
    assert int(store.meta("debt_checked_height")) == last["height"]
    # Rebuilt from the index: every write's root, then the chain's rows, size and root.
    rep = verify.rebuild(store.conn)
    asyncio.run(verify.check_chain(rep, rpc, store.conn))
    assert rep.ok, rep.errors
    assert rep.debt_writes_checked == 2
    assert (rep.debt_size, rep.debt_root.hex()) == (3, last["debt_current_root"])


def last_time(block: dict) -> int:
    from services.privacy.rpc import parse_time
    return parse_time(block["time"])


def test_slash_events_agree_with_their_rows():
    sc = scenario(DEBT_SCENARIO)
    rows = [a for _, a in _finalize(sc, "shieldedstaking_debt_row")]
    moved = [a for _, a in _finalize(sc, "shieldedstaking_move_slashed")]
    (sd,) = [a for _, a in _finalize(sc, "shieldedstaking_slash_debt")]
    assert [(m["move_key"], m["retained"]) for m in moved] == [(r["move_key"], r["retained"]) for r in rows]
    assert int(sd["debt"]) <= sum(int(m["debt"]) for m in moved) and int(sd["entries"]) == 2
    # The rows are the two redelegations' moves, keyed by their credit nullifiers.
    keys = [_attrs(e)["move_key"] for _, _, evs in _txs(sc) for e in evs if e["type"] == "shieldedstaking_redelegate"]
    assert keys == [r["move_key"] for r in rows]


def test_stake_notes_of_redelegations_and_padding_spends_are_indexed(indexed):
    """No chain-minted stake note: every stake note is a proof output with a
    201-byte ciphertext. Lane A always publishes two nullifiers (chain
    final-audit fixes, circuits C-2: slot 1 pads with its own nullifier when
    one note is spent). A first delegation spends two padding nullifiers; a
    redelegation spends three (lane A's note, lane A's slot-1 padding and the
    credit lane's padding) and creates two notes (the change and the labelled
    credit), its move_key the credit nullifier, published last."""
    store, _ = indexed
    sc = scenario(DEBT_SCENARIO)
    shapes = []
    for h, _, evs in _txs(sc):
        nfs = [_attrs(e)["nullifier"] for e in evs if e["type"] == "shieldedstaking_stake_nullifier"]
        notes = [_attrs(e) for e in evs if e["type"] == "shieldedstaking_stake_note"]
        kinds = [e["type"] for e in evs if e["type"] in (
            "shieldedstaking_delegate", "shieldedstaking_redelegate", "shieldedstaking_undelegate")]
        if not notes and not nfs:
            continue
        assert notes, "every msg that spends creates a note (a zero note when nothing is left)"
        assert all(len(base64.b64decode(n["ciphertext"])) == 201 and set(n) <= {"position_id", "commitment", "ciphertext",
                                                                                 "msg_index"} for n in notes)
        for n in notes:
            row = store.conn.execute("SELECT height, cm, ciphertext FROM stake_notes WHERE position = ?",
                                     (int(n["position_id"]),)).fetchone()
            assert (row[0], row[1].hex(), base64.b64encode(row[2]).decode()) == (h, n["commitment"], n["ciphertext"])
        for nf in nfs:
            assert store.conn.execute("SELECT height FROM stake_nullifiers WHERE nf = ?",
                                      (bytes.fromhex(nf),)).fetchone() == (h,)
        if "shieldedstaking_redelegate" in kinds:
            (rd,) = [_attrs(e) for e in evs if e["type"] == "shieldedstaking_redelegate"]
            assert "minted" not in rd and int(rd["credited"]) > 0 and int(rd["move_time"]) > 0
            assert (len(nfs), len(notes)) == (3, 2) and rd["move_key"] == nfs[-1]
        shapes.append((tuple(kinds), len(nfs), len(notes)))
    assert shapes[0] == (("shieldedstaking_delegate",), 2, 1), "the first delegation pads both slots"
    assert [s for s in shapes if s[0] == ("shieldedstaking_redelegate",)] == [(("shieldedstaking_redelegate",), 3, 2)] * 2
    assert any(s[0] == () for s in shapes), "the restake that clears the label"
    assert store.stake_counts()[0] == sc["blocks"][-1]["stake_tree_size"]


# --- {base}/debt_rows ------------------------------------------------------------

@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (1, 2, 100, 1000))


def _client(path: str, monkeypatch) -> ChainClient:
    monkeypatch.setattr(config, "INDEX_DB", path)
    app = FastAPI()
    app.include_router(privacy_router.router)
    return ChainClient(TestClient(app))


def test_debt_rows_stream_rebuilds_the_current_root(indexed, monkeypatch):
    """What a wallet does to clear a label or vote a labelled note: page every
    row by leaf index, rebuild the tree, check the root, read clear_before."""
    store, _ = indexed
    c = _client(store.path, monkeypatch)
    sc = scenario(DEBT_SCENARIO)
    want = [(int(a["index"]), a["move_key"], int(a["retained"]), h, h) for h, a in _finalize(sc, "shieldedstaking_debt_row")]
    last = sc["blocks"][-1]
    # Page 0 holds leaves 1 .. limit-1 (leaf 0 is the sentinel): with the
    # test-only limit 1 it is empty, so that walk starts at page 1.
    for limit in (1, 2, 100):
        rows, i = [], 1 if limit == 1 else 0
        while True:
            r = c.get("/privacy/debt_rows", params={"from_index": i, "limit": limit})
            assert r.status_code == 200, r.text
            body = r.json()
            assert r.headers["cache-control"] == "public, max-age=2", "a row can be rewritten: never immutable"
            assert body["format"] == 1
            assert body["fields"] == ["index", "key", "retained", "height", "updated_height"]
            assert (body["size"], body["root"], body["root_height"]) == (3, last["debt_current_root"], want[-1][3])
            assert (body["window_seconds"], body["clear_before"], body["clear_before_height"]) == (
                1815000, last_time(last) - 1815000, last["height"])
            rows += body["rows"]
            i = body["next_index"]
            if not body["complete"]:
                break
        assert [tuple(x) for x in rows] == want
        t = debt.DebtTree()
        for idx, key, retained, _, _ in rows:
            assert t.set(int(key, 16), retained) == idx
        assert t.root().to_bytes(32, "big").hex() == body["root"]
    s = c.get("/privacy/status").json()
    assert s["debt_tree_size"] == 3


@pytest.mark.parametrize("params", [{"from_index": 1, "limit": 2}, {"limit": 5}, {"from_index": 3, "limit": 2}])
def test_debt_rows_paging_follows_the_rules(indexed, monkeypatch, params):
    store, _ = indexed
    r = _client(store.path, monkeypatch).get("/privacy/debt_rows", params=params)
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store"


def test_empty_debt_rows(tmp_path, monkeypatch):
    path = str(tmp_path / "empty.db")
    seed_chain(path)
    body = _client(path, monkeypatch).get("/privacy/debt_rows").json()
    assert (body["rows"], body["size"], body["root"], body["root_height"], body["next_index"], body["complete"]) == (
        [], 0, EMPTY, None, 1, False)
    assert (body["window_seconds"], body["clear_before"], body["clear_before_height"]) == (None, None, None)


# --- a rewritten row -------------------------------------------------------------

K1, K2 = (0x1234).to_bytes(32, "big"), (0x0abc).to_bytes(32, "big")


def _row(t: debt.DebtTree, key: bytes, retained: int) -> events.DebtRow:
    idx = t.set(int.from_bytes(key, "big"), retained)
    return events.DebtRow(key, retained, idx, t.root().to_bytes(32, "big"))


def _apply(store: Store, height: int, *rows: events.DebtRow) -> None:
    store.apply(events.BlockDelta(height=height, time=height, hash=f"H{height}", debt_rows=list(rows)))


def test_a_rewritten_row_keeps_its_leaf_and_the_stream_follows(tmp_path, monkeypatch):
    path = str(tmp_path / "r.db")
    seed_chain(path)
    store = Store(path)
    t = debt.DebtTree()
    _apply(store, 1, _row(t, K1, 900), _row(t, K2, 400))
    _apply(store, 2)
    _apply(store, 3, _row(t, K1, 850))  # a second slash of the first move
    rows = store.conn.execute("SELECT idx, key, retained, height, updated_height FROM debt_rows ORDER BY idx").fetchall()
    assert rows == [(1, K1, 850, 1, 3), (2, K2, 400, 1, 1)]
    assert store.debt_size() == 3 and store.debt_root() == (t.root().to_bytes(32, "big"), 3)
    rep = verify.rebuild(store.conn)
    assert rep.ok, rep.errors
    assert rep.debt_writes_checked == 3 and rep.debt_root == t.root().to_bytes(32, "big")
    body = _client(path, monkeypatch).get("/privacy/debt_rows").json()
    assert body["rows"] == [[1, K1.hex(), 850, 1, 3], [2, K2.hex(), 400, 1, 1]]
    assert (body["root"], body["root_height"]) == (t.root().to_bytes(32, "big").hex(), 3)


@pytest.mark.parametrize("second,match", [
    (lambda r: events.DebtRow(K2, 400, 3, r.root), "at leaf 3, expected 2"),    # a gap
    (lambda r: events.DebtRow(K2, 400, 1, r.root), "at leaf 1, expected 2"),    # a new key at a used leaf
    (lambda r: events.DebtRow(K1, 800, 2, r.root), "rewritten at leaf 2"),      # a known key elsewhere
    (lambda r: events.DebtRow(K1, 901, 1, r.root), "rose from 900 to 901"),     # retained rising
])
def test_debt_rows_out_of_order_are_refused(tmp_path, second, match):
    store = Store(str(tmp_path / "x.db"))
    first = _row(debt.DebtTree(), K1, 900)
    _apply(store, 1, first)
    with pytest.raises(Inconsistent, match=match):
        _apply(store, 2, second(first))
    assert store.last_height() == 1 and store.debt_size() == 2, "the block was refused whole"


def test_a_tampered_debt_row_is_caught(indexed):
    store, rpc = indexed
    store.conn.execute("UPDATE debt_rows SET retained = retained - 1 WHERE idx = 2")
    rep = verify.rebuild(store.conn)
    assert any("is not its last write" in e for e in rep.errors)
    asyncio.run(verify.check_chain(rep, rpc, store.conn))
    assert any("slash debt row at leaf 2" in e for e in rep.errors)


def test_a_tampered_debt_write_is_caught(indexed):
    store, rpc = indexed
    store.conn.execute("UPDATE debt_writes SET retained = retained + 1 WHERE idx = 1")
    rep = verify.rebuild(store.conn)
    assert any("chain emitted root" in e for e in rep.errors)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("slash debt tree: chain root" in e for e in rep.errors)


# --- the indexer against Query/DebtTree --------------------------------------------

def test_debt_rows_missing_from_the_index_halt(tmp_path):
    """Rows imported at genesis emit no events: the size check catches them."""
    sc = copy.deepcopy(scenario(DEBT_SCENARIO))
    rpc = FakeRPC(sc)
    real = rpc.abci_query

    async def more_rows(path, data=b"", height=None):
        out = await real(path, data, height)
        if path.endswith("/DebtTree"):
            f = proto_fields(out)
            out += b"\x10" + bytes([(f.get(2) or [0])[-1] + 2])  # size, repeated: the last one wins
        return out
    rpc.abci_query = more_rows
    with pytest.raises(Halted, match="slash debt tree of [0-9]+, the index"):
        sync(Indexer(Store(str(tmp_path / "i.db")), rpc))


def test_a_debt_root_other_than_the_chain_halts(tmp_path):
    sc = copy.deepcopy(scenario(DEBT_SCENARIO))
    for b in sc["blocks"]:
        for e in b["block_results"].get("finalize_block_events") or []:
            if e["type"] == "shieldedstaking_debt_row":
                next(a for a in e["attributes"] if a["key"] == "root")["value"] = "07" * 32
    with pytest.raises(Halted, match="slash debt root"):
        sync(Indexer(Store(str(tmp_path / "i.db")), FakeRPC(sc)))


# --- malformed slash events --------------------------------------------------------

V1, V2 = "earthvaloper1src", "earthvaloper1dst"


def _ev(type_: str, **attrs) -> dict:
    return {"type": type_, "attributes": [{"key": k, "value": str(v)} for k, v in attrs.items()] +
            [{"key": "mode", "value": "BeginBlock"}]}


def _slash(key="11" * 32, retained=90, debt_=10, index=1, root="22" * 32, total=None, src=V1, dst=V2):
    return [_ev("shieldedstaking_debt_row", move_key=key, retained=retained, index=index, root=root),
            _ev("shieldedstaking_move_slashed", move_key=key, src_validator=src, dst_validator=dst, debt=debt_,
                retained=retained),
            _ev("shieldedstaking_slash_debt", src_validator=V1, dst_validator=V2, value=50,
                debt=debt_ if total is None else total, entries=1)]


def _parse(fin, txs=()):
    return events.parse_block(5, 0, "H", {"height": "5", "finalize_block_events": fin,
                                          "txs_results": [{"code": 0, "events": list(txs)}] if txs else []})


def test_a_slash_parses_to_its_row():
    d = _parse(_slash())
    assert d.debt_rows == [events.DebtRow(bytes([0x11]) * 32, 90, 1, bytes([0x22]) * 32)]
    # The book may cap the slash_debt below its moves' sum.
    assert _parse(_slash(total=3)).debt_rows


@pytest.mark.parametrize("fin,match", [
    (_slash()[:1], "without its move_slashed"),
    (_slash()[:1] + _slash(key="33" * 32)[:1], "without its move_slashed"),
    (_slash()[:2], "without its slash_debt"),
    (_slash()[1:], "does not follow its debt row"),
    ([_slash()[0], _slash(retained=91)[1], _slash()[2]], "does not follow its debt row"),
    ([_slash()[0], _slash(key="33" * 32)[1], _slash()[2]], "does not follow its debt row"),
    (_slash(total=11), "debt 11, its moves owe 10"),
    (_slash(src="earthvaloper1other"), "a move of earthvaloper1other"),
    (_slash(key="00" * 32), "the sentinel's"),
    (_slash(index=0), "index 0"),
    (_slash(retained=2**63), "above a note's maximum"),
    (_slash(retained=-1), "negative"),
    (_slash(root="22" * 31), "31 bytes"),
])
def test_malformed_slash_events_are_refused(fin, match):
    with pytest.raises(events.EventError, match=match):
        _parse(fin)


def _redelegate(**over):
    a = dict(src_validator=V1, dst_validator=V2, derth=10, value=11, credited=9, queued=1, bonded=10,
             completion_time=1, move_key="44" * 32, move_time=100)
    a.update(over)
    return {"type": "shieldedstaking_redelegate", "attributes": [{"key": k, "value": str(v)} for k, v in a.items()]}


def _nf(nf: str, index: int) -> dict:
    return {"type": "shieldedstaking_stake_nullifier", "attributes": [{"key": "nullifier", "value": nf},
                                                                     {"key": "index", "value": str(index)}]}


def test_a_redelegation_names_its_credit_nullifier():
    assert _parse([], [_nf("55" * 32, 1), _nf("44" * 32, 2), _redelegate()]).debt_rows == []


@pytest.mark.parametrize("ev,match", [
    (_redelegate(minted=9), "before dff3a9b"),
    (_redelegate(move_key="66" * 32), "not a stake nullifier of this block"),
    (_redelegate(credited="x"), "credited: not an integer"),
    (_redelegate(move_time=-1), "move_time: negative"),
])
def test_malformed_redelegations_are_refused(ev, match):
    with pytest.raises(events.EventError, match=match):
        _parse([], [_nf("55" * 32, 1), _nf("44" * 32, 2), ev])
