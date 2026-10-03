"""The indexer over recorded chain blocks: events, ordering, resumption, refusals."""
import asyncio
import base64
import copy

import pytest

from services.privacy import events, verify
from services.privacy.indexer import Halted, Indexer
from services.privacy.rpc import RPCError, parse_time, proto_fields
from services.privacy.store import Inconsistent, Store
from tests.privacy_fixtures import SCENARIOS, FakeRPC, load


def run(coro):
    return asyncio.run(coro)


def sync(idx: Indexer) -> None:
    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    run(go())


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "index.db")


@pytest.mark.parametrize("name", SCENARIOS)
def test_indexes_every_scenario_and_matches_the_keepers(db, name):
    sc = load(name)
    store = Store(db)
    idx = Indexer(store, FakeRPC(sc), batch=7)
    sync(idx)
    last = sc["blocks"][-1]
    assert store.last_height() == last["height"]
    notes, ids, _ = store.counts()
    assert (notes, ids) == (last["note_tree_size"], last["identity_tree_size"])
    # Every root the chain emitted was indexed, at the size the keeper had.
    for b in sc["blocks"]:
        row = store.conn.execute("SELECT root, tree_size FROM note_roots WHERE height = ?", (b["height"],)).fetchone()
        if row:
            assert row[0].hex() == b["note_latest_root"] and row[1] == b["note_tree_size"]
        row = store.conn.execute("SELECT root, tree_size FROM identity_roots WHERE height = ?", (b["height"],)).fetchone()
        if row:
            assert row[0].hex() == b["identity_latest_root"] and row[1] == b["identity_tree_size"]
        row = store.conn.execute("SELECT root, tree_size FROM stake_roots WHERE height = ?", (b["height"],)).fetchone()
        if row:
            assert row[0].hex() == b["stake_latest_root"] and row[1] == b["stake_tree_size"]
    assert store.stake_counts()[0] == last.get("stake_tree_size", 0)
    # And the Python rebuild reproduces every one of them, and the chain's
    # trees at the synced height.
    rep = verify.rebuild(store.conn, all_roots=True)
    run(verify.check_chain(rep, idx.rpc))
    assert rep.ok, rep.errors
    assert rep.note_root.hex() == last["note_current_root"]
    assert rep.identity_root.hex() == last["identity_current_root"]
    if last.get("stake_tree_size"):
        assert rep.stake_root.hex() == last["stake_latest_root"]
    # One note-discovery rule: every note the chain minted or shielded
    # carries its 177-byte amount-blind v2 ciphertext.
    bad = store.conn.execute("SELECT COUNT(*) FROM notes WHERE amount IS NOT NULL AND length(ciphertext) != 177").fetchone()[0]
    assert bad == 0
    bad = store.conn.execute("SELECT COUNT(*) FROM stake_notes WHERE spc IS NOT NULL AND length(ciphertext) IS NOT 177").fetchone()[0]
    assert bad == 0


def test_personhood_scenario_covers_appends_zeroings_mints_and_rates(db):
    store = Store(db)
    sync(Indexer(store, FakeRPC(load("TestPrivatePersonhood"))))
    c = store.conn
    (zeroed,) = c.execute("SELECT COUNT(*) FROM identity_leaves WHERE zeroed_height IS NOT NULL").fetchone()
    assert zeroed >= 1, "switches and expiry zero leaves"
    (zw,) = c.execute("SELECT COUNT(*) FROM identity_writes WHERE zeroed = 1").fetchone()
    assert zw == zeroed
    (minted,) = c.execute("SELECT COUNT(*) FROM notes WHERE amount LIKE '%uanml'").fetchone()
    assert minted >= 1, "registration and claims mint ANML notes with a public value"
    (hidden,) = c.execute("SELECT COUNT(*) FROM notes WHERE amount IS NULL").fetchone()
    assert hidden >= 1, "bundle outputs stay hidden"


def test_staking_scenario_records_epoch_rates(db):
    store = Store(db)
    sync(Indexer(store, FakeRPC(load("TestPrivateStakingLifecycle"))))
    rows = store.conn.execute("SELECT validator, epoch, rate FROM rates ORDER BY height").fetchall()
    assert rows and all(v.startswith("earthvaloper") for v, _, _ in rows)
    assert all(e is not None for _, e, _ in rows)
    epochs = [e for _, e, _ in rows]
    assert epochs == sorted(epochs)


def test_resumes_where_it_stopped_and_is_idempotent(db):
    sc = load("TestPrivatePersonhood")
    rpc = FakeRPC(sc, tip=10)
    store = Store(db)
    sync(Indexer(store, rpc))
    assert store.last_height() == 10
    # Re-applying an indexed block is a no-op.
    b = sc["blocks"][9]
    delta = events.parse_block(10, parse_time(b["time"]), b["hash"], b["block_results"])
    assert store.apply(delta) is False
    store.close()

    rpc.tip = len(sc["blocks"])
    store = Store(db)
    idx = Indexer(store, rpc)
    run(idx.prepare())
    assert idx.next_height == 11
    sync(idx)
    rep = verify.rebuild(store.conn, all_roots=True)
    assert rep.ok, rep.errors


def test_a_different_chain_behind_the_rpc_halts(db):
    sc = load("TestShieldedPoolEndToEnd")
    store = Store(db)
    sync(Indexer(store, FakeRPC(sc)))
    other = copy.deepcopy(sc)
    for b in other["blocks"]:
        b["hash"] = "00" * 32
    idx = Indexer(store, FakeRPC(other))
    with pytest.raises(Halted, match="different chain"):
        run(idx.prepare())
    # The halt is sticky: a restart refuses until an operator clears it.
    with pytest.raises(Halted):
        run(Indexer(store, FakeRPC(sc)).prepare())


def test_a_block_that_does_not_follow_the_indexed_one_halts(db):
    """Re-audit K14: continuity is checked on every block, not only at start.
    An RPC swapped mid-run (a load balancer, a relaunch) serves blocks whose
    parent is not the block the index holds."""
    sc = load("TestPrivatePersonhood")
    rpc = FakeRPC(sc, tip=10)
    store = Store(db)
    idx = Indexer(store, rpc, batch=4)
    sync(idx)
    assert store.last_height() == 10
    rpc.tip = len(sc["blocks"])
    rpc.parents[13] = "AB" * 32
    with pytest.raises(Halted, match="block 13 names parent"):
        while run(idx.step()):
            pass
    assert store.last_height() == 12, "nothing from the other chain is applied"
    assert "parent" in store.meta("halted")


def test_parent_check_survives_a_restart_and_ignores_case(db):
    sc = load("TestShieldedPoolEndToEnd")
    rpc = FakeRPC(sc, tip=4)
    store = Store(db)
    sync(Indexer(store, rpc))
    # After a restart the first block fetched must follow the last indexed one.
    rpc.tip = 6
    rpc.parents[5] = sc["blocks"][3]["hash"].lower()  # the same hash, other case
    sync(Indexer(store, rpc))
    assert store.last_height() == 6
    rpc.tip = len(sc["blocks"])
    rpc.parents[7] = "00" * 32
    with pytest.raises(Halted, match="block 7 names parent"):
        sync(Indexer(store, rpc))
    assert store.last_height() == 6


def test_a_different_chain_id_halts(db):
    sc = load("TestShieldedPoolEndToEnd")
    store = Store(db)
    sync(Indexer(store, FakeRPC(sc, tip=2)))
    other = dict(sc, chain_id="earth-2")
    with pytest.raises(Halted, match="earth-2"):
        run(Indexer(store, FakeRPC(other)).prepare())


def test_starting_past_the_first_note_halts(db):
    sc = load("TestPrivatePersonhood")
    first = next(b["height"] for b in sc["blocks"] if b["note_tree_size"])
    idx = Indexer(Store(db), FakeRPC(sc), start_height=first + 1)
    run(idx.prepare())
    with pytest.raises(Halted, match="history"):
        while run(idx.step()):
            pass


def test_starting_below_the_nodes_earliest_block_halts(db):
    idx = Indexer(Store(db), FakeRPC(load("TestShieldedPoolEndToEnd"), earliest=3), start_height=1)
    with pytest.raises(Halted, match="earliest"):
        run(idx.prepare())


def test_rpc_errors_are_retried_not_fatal(db):
    sc = load("TestShieldedPoolEndToEnd")
    rpc = FakeRPC(sc)
    store = Store(db)
    idx = Indexer(store, rpc)

    async def go():
        stop = asyncio.Event()
        rpc.fail_next = RPCError("connection reset")
        task = asyncio.create_task(idx.run(stop, poll_seconds=0.01))
        for _ in range(500):
            if store.last_height() == rpc.tip:
                break
            await asyncio.sleep(0.01)
        stop.set()
        await task

    run(go())
    assert store.last_height() == rpc.tip and idx.halted is None


def test_failed_tx_ante_events_are_indexed(db):
    """A private tx whose msg failed after the ante: its notes and nullifiers persisted.

    SDK v0.53 commits the ante's writes and returns only the ante's events in
    the failed tx's result; the indexer must take them (verified against
    baseapp in the SDK's own test harness — see services/privacy/events.py).
    """
    sc = load("TestShieldedPoolEndToEnd")
    blocks = copy.deepcopy(sc["blocks"])
    # Find a successful private tx with notes, and mark it failed with only
    # its ante events left, as DeliverTx reports a msg failure.
    for b in blocks:
        for tx in b["block_results"].get("txs_results") or []:
            if not tx.get("code") and any(e["type"] == "shielded_nullifier" for e in tx.get("events") or []):
                want_n = sum(e["type"] == "shielded_note" for e in tx["events"])
                want_f = sum(e["type"] == "shielded_nullifier" for e in tx["events"])
                tx["code"] = 5
                tx["log"] = "msg failed"
                tx["events"] = [e for e in tx["events"] if e["type"] in ("tx", "shielded_nullifier", "shielded_note", "shielded_fee")]
                target = b["height"]
                break
        else:
            continue
        break
    store = Store(db)
    sync(Indexer(store, FakeRPC(dict(sc, blocks=blocks))))
    (n,) = store.conn.execute("SELECT COUNT(*) FROM notes WHERE height = ?", (target,)).fetchone()
    (f,) = store.conn.execute("SELECT COUNT(*) FROM nullifiers WHERE height = ?", (target,)).fetchone()
    assert want_n >= 2 and want_f >= 2, "a bundle has at least two actions"
    assert (n, f) == (want_n, want_f), "the failed tx's action outputs and nullifiers"
    rep = verify.rebuild(store.conn, all_roots=True)
    assert rep.ok, rep.errors


def test_out_of_order_notes_are_refused(db):
    sc = load("TestShieldedPoolEndToEnd")
    blocks = copy.deepcopy(sc["blocks"])
    for b in blocks:
        for tx in b["block_results"].get("txs_results") or []:
            evs = tx.get("events") or []
            idx = [i for i, e in enumerate(evs) if e["type"] == "shielded_note"]
            if len(idx) >= 2:
                evs[idx[0]], evs[idx[1]] = evs[idx[1]], evs[idx[0]]
                break
        else:
            continue
        break
    idx = Indexer(Store(db), FakeRPC(dict(sc, blocks=blocks)))
    with pytest.raises(Halted, match="position"):
        sync(idx)


def test_double_spent_nullifier_is_refused(db):
    sc = load("TestShieldedPoolEndToEnd")
    store = Store(db)
    sync(Indexer(store, FakeRPC(sc, tip=len(sc["blocks"]))))
    nf = store.conn.execute("SELECT nf FROM nullifiers LIMIT 1").fetchone()[0]
    d = events.BlockDelta(height=store.last_height() + 1, time=0, hash="X", nullifiers=[nf])
    with pytest.raises(Inconsistent, match="spent twice"):
        store.apply(d)
    assert store.last_height() == len(sc["blocks"]), "nothing of the refused block was written"


def test_block_events_are_ordered_begin_txs_end():
    res = {
        "height": "5",
        "txs_results": [{"code": 0, "events": [{"type": "shielded_note", "attributes": [
            {"key": "position", "value": "1"}, {"key": "commitment", "value": "11" * 32}, {"key": "ciphertext", "value": ""}]}]}],
        "finalize_block_events": [
            {"type": "shielded_note", "attributes": [
                {"key": "position", "value": "0"}, {"key": "commitment", "value": "00" * 32},
                {"key": "ciphertext", "value": base64.b64encode(b"c").decode()}, {"key": "mode", "value": "BeginBlock"}]},
            {"type": "shielded_root", "attributes": [
                {"key": "root", "value": "22" * 32}, {"key": "tree_size", "value": "3"}, {"key": "height", "value": "5"},
                {"key": "mode", "value": "EndBlock"}]},
            {"type": "shielded_mint", "attributes": [
                {"key": "module", "value": "x"}, {"key": "amount", "value": "5uanml"}, {"key": "position", "value": "2"},
                {"key": "mode", "value": "EndBlock"}]},
            {"type": "shielded_note", "attributes": [
                {"key": "position", "value": "2"}, {"key": "commitment", "value": "33" * 32}, {"key": "ciphertext", "value": ""},
                {"key": "mode", "value": "EndBlock"}]},
        ],
    }
    # The mint names position 2 before its note event: a malformed order the
    # chain never emits (MintNote appends, then emits) — refused, not guessed.
    with pytest.raises(events.EventError):
        events.parse_block(5, 0, "H", res)
    fb = res["finalize_block_events"]
    fb[2], fb[3] = fb[3], fb[2]
    d = events.parse_block(5, 0, "H", res)
    assert [n.position for n in d.notes] == [0, 1, 2]
    assert d.notes[0].ciphertext == b"c" and d.notes[2].amount == "5uanml"
    assert d.note_root.tree_size == 3


@pytest.mark.parametrize("event", ["shielded_mint", "shielded_shield"])
def test_a_mint_ciphertext_must_match_its_note(event):
    ct = base64.b64encode(bytes(177)).decode()

    def res(mint_ct):
        return {"height": "5", "txs_results": [{"code": 0, "events": [
            {"type": "shielded_note", "attributes": [
                {"key": "position", "value": "0"}, {"key": "commitment", "value": "11" * 32}, {"key": "ciphertext", "value": ct}]},
            {"type": event, "attributes": [
                {"key": "amount", "value": "5uerth"}, {"key": "position", "value": "0"}, {"key": "ciphertext", "value": mint_ct}]}]}]}

    d = events.parse_block(5, 0, "H", res(ct))
    assert d.notes[0].ciphertext == bytes(177) and d.notes[0].amount == "5uerth"
    with pytest.raises(events.EventError, match="differs"):
        events.parse_block(5, 0, "H", res(base64.b64encode(bytes([1]) * 177).decode()))


def test_parse_time_and_proto_fields():
    assert parse_time("2026-09-30T12:00:00.123456789Z") == 1790769600
    assert parse_time("2026-09-30T12:00:00Z") == 1790769600
    msg = bytes([0x08, 0x96, 0x01, 0x12, 0x02, 0x61, 0x62])
    assert proto_fields(msg) == {1: [150], 2: [b"ab"]}


def test_the_chain_genesis_is_recorded_once(db):
    sc = load("TestPrivatePersonhood")
    first = min(sc["blocks"], key=lambda b: b["height"])
    store = Store(db)
    # Even when indexing starts past it: the identity is the chain's first block.
    run(Indexer(store, FakeRPC(sc, tip=5), start_height=3).prepare())
    assert store.meta("genesis_hash") == first["hash"].lower()
    assert store.meta("genesis_height") == str(first["height"])
    # A later prepare never rewrites it (the block-hash check is what catches
    # a different chain behind the RPC).
    run(Indexer(store, FakeRPC(sc, earliest=3)).prepare())
    assert store.meta("genesis_hash") == first["hash"].lower()


def test_failed_tx_with_only_failure_code_still_counts_every_event(db):
    """L4 guard: a tx result with code != 0 is not filtered anywhere in parse_block."""
    sc = load("TestShieldedPoolEndToEnd")
    blocks = copy.deepcopy(sc["blocks"])
    for b in blocks:
        for tx in b["block_results"].get("txs_results") or []:
            tx["code"] = 11  # every tx "failed"; events unchanged
    want = Store(str(db) + ".ok")
    sync(Indexer(want, FakeRPC(sc)))
    got = Store(db)
    sync(Indexer(got, FakeRPC(dict(sc, blocks=blocks))))
    assert got.counts() == want.counts()


# --- audit 3: relaunch under the same chain id ---------------------------------

class _CometLike(FakeRPC):
    """CometBFT v0.38 /blockchain: minHeight above the tip is an RPC error."""

    async def block_metas(self, lo, hi):
        if lo > self.tip:
            raise RPCError(f"blockchain: min height {lo} can't be greater than max height {self.tip}")
        return await super().block_metas(lo, hi)


def _chain_b(sc):
    return {"chain_id": sc["chain_id"], "blocks": [dict(x, hash="B" + x["hash"][1:]) for x in sc["blocks"]]}


def _index_all(store, rpc):
    idx = Indexer(store, rpc)

    async def go():
        await idx.prepare()
        while await idx.step():
            pass
    asyncio.run(go())
    return idx


def test_a_relaunched_chain_with_a_lower_tip_halts(db):
    """audit-3 poc_relaunch_no_halt.py: chain B (same id, tip below A's last
    height) was retried forever with halted=null."""
    sc = load("TestPrivatePersonhood")
    store = Store(db)
    _index_all(store, _CometLike(sc))
    last = store.last_height()
    rpc_b = _CometLike(_chain_b(sc), tip=max(2, last // 3))
    idx2 = Indexer(store, rpc_b, check_sizes=False)

    async def restart():
        stop = asyncio.Event()
        task = asyncio.create_task(idx2.run(stop, poll_seconds=0.01))
        await asyncio.wait_for(task, timeout=5)  # returns on its own: halted
    asyncio.run(restart())
    halted = store.meta("halted")
    assert halted and "genesis" in halted
    assert store.last_height() == last


def test_genesis_is_rechecked_on_every_prepare(db):
    sc = load("TestPrivatePersonhood")
    store = Store(db)
    _index_all(store, FakeRPC(sc, tip=5))
    # Same chain id, same tip-or-higher, different first block: a relaunch
    # whose height already passed the index. Only the genesis tells.
    b = _chain_b(sc)
    for blk in b["blocks"]:
        if blk["height"] == store.last_height():
            blk["hash"] = store.block_hash(blk["height"])  # even the last indexed block agrees
    idx = Indexer(store, FakeRPC(b), check_sizes=False)
    with pytest.raises(Halted):
        asyncio.run(idx.prepare())
    assert "genesis" in store.meta("halted")


def test_a_tip_below_the_index_halts_unless_catching_up(db):
    sc = load("TestPrivatePersonhood")
    store = Store(db)
    _index_all(store, FakeRPC(sc))
    last = store.last_height()

    class Syncing(FakeRPC):
        async def status(self):
            return dict(await super().status(), catching_up=True)

    idx = Indexer(store, Syncing(sc, tip=last - 3), check_sizes=False)
    with pytest.raises(RPCError):
        asyncio.run(idx.prepare())
    assert store.meta("halted") is None, "a syncing node of the same chain is waited for"
    idx = Indexer(store, FakeRPC(sc, tip=last - 3), check_sizes=False)
    with pytest.raises(Halted):
        asyncio.run(idx.prepare())
    assert "below the indexed height" in store.meta("halted")


def test_status_shows_the_halt_reason(db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import config
    from routers import privacy

    sc = load("TestPrivatePersonhood")
    store = Store(db)
    _index_all(store, FakeRPC(sc))
    with pytest.raises(Halted):
        asyncio.run(Indexer(store, FakeRPC(_chain_b(sc)), check_sizes=False).prepare())
    monkeypatch.setattr(config, "INDEX_DB", db)
    app = FastAPI()
    app.include_router(privacy.router)
    assert "genesis" in TestClient(app).get("/privacy/status").json()["halted"]


def test_a_skipped_tree_size_check_warns(db, caplog):
    sc = load("TestPrivatePersonhood")

    class Pruned(FakeRPC):
        async def abci_query(self, path, data=b"", height=None):
            raise RPCError("pruned")

    import logging
    with caplog.at_level(logging.WARNING, logger="services.privacy.indexer"):
        _index_all(Store(db), Pruned(sc))
    warns = [r for r in caplog.records if "tree size check" in r.getMessage()]
    assert warns and all(r.levelno == logging.WARNING for r in warns)
    assert len(warns) < 5, "throttled"


def _validator_event(v: str, rate: str) -> dict:
    return {"type": "shieldedstaking_epoch_validator", "attributes": [
        {"key": "validator", "value": v}, {"key": "rate", "value": rate}, {"key": "supply", "value": "1"},
        {"key": "rewards", "value": ""}, {"key": "delegated", "value": "0"}, {"key": "undelegated", "value": "0"},
        {"key": "mode", "value": "EndBlock"}]}


def test_rates_of_a_sweep_past_200_validators_keep_their_epoch(db):
    """x/shieldedstaking sweeps EpochValidatorLimit (200) books a block: the
    rest of an epoch's validators come in later blocks with no epoch event."""
    store = Store(db)
    first = {"height": "1", "txs_results": [], "finalize_block_events": [
        *(_validator_event(f"earthvaloper{i:03d}", "1.0") for i in range(200)),
        {"type": "shieldedstaking_epoch", "attributes": [{"key": "epoch", "value": "7"}, {"key": "mode", "value": "EndBlock"}]},
    ]}
    cont = {"height": "2", "txs_results": [], "finalize_block_events": [
        *(_validator_event(f"earthvaloper{i:03d}", "1.0") for i in range(200, 250)),
    ]}
    store.apply(events.parse_block(1, 0, "H1", first))
    store.apply(events.parse_block(2, 1, "H2", cont))
    rows = store.conn.execute("SELECT epoch, COUNT(*) FROM rates GROUP BY epoch").fetchall()
    assert rows == [(7, 250)]
