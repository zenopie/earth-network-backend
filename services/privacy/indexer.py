"""Follows the chain block by block into the privacy index.

    python -m services.privacy.indexer          # standalone, until interrupted

or, inside the API process, started by main.py when INDEXER_ENABLED.

CometBFT finality is instant: a committed block is never reverted, so the
indexer only ever moves forward and never rolls back. What it does guard
against is the RPC pointing at a different chain than the one indexed (a
relaunch under the same chain id, a misconfigured URL, an RPC swapped behind
a load balancer): the chain id and the hash of the last indexed block are
checked on every prepare (every start, and again after any RPC error), as is
the hash of the block at genesis_height (a relaunch keeps the chain id, not
its first block), and every block applied after that must name the indexed
block before it as its parent (header.last_block_id). A node whose tip is
below the indexed height, and which is not catching up, is not serving the
indexed chain. Any of these halts the indexer: the reason is in
/privacy/status "halted" — wipe INDEX_DB to start over.

Blocks are fetched in batches (block_results concurrently, block times and
hashes from /blockchain) and applied strictly in order, one SQLite
transaction each; see store.py for what applying checks. After each batch
the indexed tree sizes are compared with the chain's own (an abci_query of
x/shielded Tree, x/personhood IdentityTree, x/shieldedstaking StakeTree,
StakeNullifierTree and DebtTree at that height; the debt tree's root too,
against the root of the last debt row event). That catches
history the index never saw — notes or leaves imported at genesis, which emit
no events, or a start height past the first private tx — which events alone
cannot reveal.

The RPC is trusted for block_results. The next header's last_results_hash
does not authenticate them: CometBFT v0.38 hashes only each tx result's
deterministic fields (code, data, gas_wanted, gas_used) — no events — and
not finalize_block_events at all, which is where every mint, root and rate
is. Checking it would cost a /block call a block and prove nothing the index
reads. What does bound a lying RPC is the tree-size check above (state the
chain committed to, but read from the same RPC) and verify.py / bin/
verify-trees.py, which rebuild every tree and compare roots with the chain's.
Point INDEXER_RPC_URL at a node you run or trust.

Once caught up, it also keeps the handle directory (services/privacy/
handles): the chain's Handles query read whole at the last applied height,
again after a block with a handle event, once block time passes the
snapshot's earliest status change, and at least every
HANDLES_MAX_AGE_SECONDS. A failed or malformed read keeps the previous
snapshot (logged); the trees go on regardless.

Needs a node that keeps block results from the start height on
(storage.discard_abci_responses = false, the default, and no block pruning
below it).

Pages are served immutable only up to meta verified_height, the last
height whose tree sizes matched the chain's (or the last applied, with
the check off), and nothing under {base} is served while halted.
"""
import asyncio
import logging

import config

from . import handles as handles_mod
from . import store as store_mod
from .events import EventError, parse_block
from services.zk.debt import EMPTY_ROOT as DEBT_EMPTY_ROOT

from .rpc import CometRPC, RPCError, proto_fields, varint_field
from .store import Inconsistent, Store
from .verify import (DEBT_TREE_QUERY, IDENTITY_TREE_QUERY, NOTE_TREE_QUERY, STAKE_NF_TREE_QUERY,
                     STAKE_NF_TREE_REQUEST, STAKE_TREE_QUERY, debt_request)

logger = logging.getLogger(__name__)

# Asked with limit 1: one row, not 1,000.
DEBT_TREE_REQUEST = debt_request(0, 1)


class Halted(Exception):
    """The index cannot continue without an operator: it would diverge from the chain."""


class Indexer:
    def __init__(self, store: Store, rpc: CometRPC, *, start_height: int = 0, batch: int = 20,
                 concurrency: int = 8, check_sizes: bool = True, handles: bool = True,
                 handles_limit: int = 1000, handles_max_age: int = 3600, handles_max: int = 200_000,
                 handles_min_blocks: int = 0, handles_stale_blocks: int = 30):
        self.store = store
        self.rpc = rpc
        self.start_height = start_height
        self.batch = batch
        self._sem = asyncio.Semaphore(concurrency)
        self.check_sizes = check_sizes
        self.handles = handles
        self.handles_limit = handles_limit
        self.handles_max_age = handles_max_age
        self.handles_max = handles_max
        self.handles_min_blocks = handles_min_blocks
        self.handles_stale_blocks = handles_stale_blocks
        self._handles_stale_steps = 0
        self._handle_failures = 0
        self.tip = 0
        self.halted: str | None = store.meta("halted")
        self.next_height = 0
        # The hash of the block at next_height - 1, which the next block must
        # name as its parent. None only before the first block of a new index.
        self.prev_hash: str | None = None
        self._size_skips = 0

    # --- lifecycle ---------------------------------------------------------

    async def prepare(self) -> None:
        """Checks the RPC serves the indexed chain and picks the next height."""
        if self.halted:
            raise Halted(self.halted)
        st = await self.rpc.status()
        self.tip = st["latest_height"]
        known = self.store.meta("chain_id")
        if known is None:
            self.store.set_meta("chain_id", st["chain_id"])
        elif known != st["chain_id"]:
            self._halt(f"RPC serves chain {st['chain_id']}, index holds {known}")
        if self.store.meta("genesis_hash") is None:
            # The chain's identity across relaunches (earth-1 has been
            # relaunched under the same chain id): the hash of its first
            # block, read once from a full-history node and never changed.
            # The /privacy URLs carry it, so a CDN-cached page of an earlier
            # chain is never what a wallet asks for.
            e = st["earliest_height"]
            metas = await self.rpc.block_metas(e, e)
            if e not in metas:
                raise RPCError(f"no block meta for the node's earliest block {e}")
            self.store.set_meta("genesis_hash", metas[e][0].lower())
            self.store.set_meta("genesis_height", str(e))
        else:
            await self._check_genesis(st)
        last = self.store.last_height()
        if last:
            if self.tip < last:
                if st.get("catching_up"):
                    # A node still block-syncing is behind, not elsewhere:
                    # its genesis matched above. Wait for it.
                    raise RPCError(f"the node is catching up at {self.tip}, below the indexed height {last}")
                # A relaunch under the same chain id restarts low; a node
                # that is not syncing and is below what was indexed from it
                # is not serving the chain the index holds.
                self._halt(f"the RPC's tip {self.tip} is below the indexed height {last} and the node is not "
                           f"catching up: a relaunched chain or a node that lost blocks")
            metas = await self.rpc.block_metas(last, last)
            if last not in metas:
                raise RPCError(f"no block meta for the indexed tip {last}")
            if metas[last][0].upper() != (self.store.block_hash(last) or "").upper():
                self._halt(f"block {last} hash is {metas[last][0]} on the RPC, {self.store.block_hash(last)} in the index: a different chain")
            self.next_height = last + 1
            self.prev_hash = self.store.block_hash(last)
        else:
            start = self.start_height or st["earliest_height"]
            if start < st["earliest_height"]:
                self._halt(f"start height {start} is below the node's earliest block {st['earliest_height']}; use a full-history node (rpc.erth.network)")
            self.next_height = start

    async def _check_genesis(self, st: dict) -> None:
        """Halts unless the block at genesis_height still has genesis_hash.

        Every prepare (every start, and again after any RPC error): a
        relaunch keeps the chain id, so only the first block tells the chains
        apart. A node pruned past it cannot answer; the last indexed block's
        hash (prepare, next) is then the only check.
        """
        gh = int(self.store.meta("genesis_height") or 0)
        want = (self.store.meta("genesis_hash") or "").lower()
        if not gh or gh < st["earliest_height"]:
            logger.warning("privacy indexer: the node's earliest block %d is past genesis height %s; "
                           "the genesis hash is not re-checked", st["earliest_height"], gh or "(unknown)")
            return
        if gh > st["latest_height"]:
            self._halt(f"the RPC's tip {st['latest_height']} is below the genesis height {gh} the index was built from: "
                       f"a relaunched chain")
        metas = await self.rpc.block_metas(gh, gh)
        if gh not in metas:
            raise RPCError(f"no block meta for genesis height {gh}")
        if metas[gh][0].lower() != want:
            self._halt(f"block {gh} hash is {metas[gh][0].lower()} on the RPC, genesis {want} in the index: "
                       f"a relaunched or different chain under chain id {st['chain_id']}")

    def _halt(self, reason: str) -> None:
        self.halted = reason
        self.store.set_meta("halted", reason)
        logger.error("privacy indexer halted: %s", reason)
        raise Halted(reason)

    # --- following ---------------------------------------------------------

    async def _results(self, height: int) -> dict:
        async with self._sem:
            return await self.rpc.block_results(height)

    async def step(self) -> int:
        """Applies the next batch up to the tip. Returns how many blocks were applied."""
        if self.halted:
            raise Halted(self.halted)
        st = await self.rpc.status()
        self.tip = st["latest_height"]
        if self.next_height - 1 > self.tip:
            # Below what was indexed: run() prepares again, which re-checks
            # the genesis and halts unless the node is merely catching up.
            raise RPCError(f"the RPC's tip {self.tip} is below the indexed height {self.next_height - 1}")
        if self.next_height > self.tip:
            return 0
        hi = min(self.tip, self.next_height + self.batch - 1)
        heights = list(range(self.next_height, hi + 1))
        metas, results = await asyncio.gather(
            self.rpc.block_metas(heights[0], heights[-1]),
            asyncio.gather(*(self._results(h) for h in heights)),
        )
        applied = 0
        for h, res in zip(heights, results):
            if h not in metas:
                raise RPCError(f"no block meta for {h}")
            block_hash, t, parent = metas[h]
            if self.prev_hash is not None and parent.upper() != self.prev_hash.upper():
                self._halt(f"block {h} names parent {parent or '(none)'}, the index has {self.prev_hash} at {h - 1}: a different chain")
            try:
                delta = parse_block(h, t, block_hash, res)
                await asyncio.to_thread(self.store.apply, delta)
            except (EventError, Inconsistent) as exc:
                self._halt(f"block {h}: {exc}")
            self.next_height = h + 1
            self.prev_hash = block_hash
            applied += 1
        if self.check_sizes:
            await self._check_sizes(heights[-1])
        else:
            await asyncio.to_thread(self.store.set_meta, "verified_height", str(heights[-1]))
        if self.handles and self.next_height > self.tip:
            await self._refresh_handles()
        if self.handles:
            await self._warn_if_handles_stale()
        return applied

    async def _refresh_handles(self) -> None:
        """Re-reads the handle directory at the last applied height when the snapshot is behind.

        Bounded (audit-5 L4): at most once every handles_min_blocks blocks
        (anyone can pay for a handle event every block); each page parsed in
        a worker thread and staged in SQLite as it arrives, so memory is one
        page whatever the directory's size; at most handles_max entries.
        """
        height = self.next_height - 1
        taken = await asyncio.to_thread(self.store.meta, "handles_height")
        if taken is not None and height - int(taken) < self.handles_min_blocks:
            return
        if not await asyncio.to_thread(self.store.handles_due, self.handles_max_age):
            return
        try:
            n, nxt = 0, None
            async for page in handles_mod.pages(self.rpc, height, limit=self.handles_limit,
                                                max_entries=self.handles_max):
                await asyncio.to_thread(self.store.stage_handles, n, page, fresh=n == 0)
                n += len(page)
                change = handles_mod.next_change(page)
                if change is not None:
                    nxt = change if nxt is None else min(nxt, change)
        except (RPCError, handles_mod.Malformed) as exc:
            await asyncio.to_thread(self.store.discard_staged_handles)
            # The snapshot stays as it was (its height says how old it is,
            # and /privacy says when it is stale); the first failure of a
            # run and every 100th after it.
            if self._handle_failures % 100 == 0:
                logger.warning("handle directory at %d not read (%d in a row): %s", height,
                               self._handle_failures + 1, exc)
            self._handle_failures += 1
            return
        self._handle_failures = 0
        when = int(self.store.meta("last_time") or 0)
        await asyncio.to_thread(self.store.commit_handles, height, when, nxt)

    async def _warn_if_handles_stale(self) -> None:
        """Logs (an alert) while the served directory is behind a handle event (audit-5 L5)."""
        stale = await asyncio.to_thread(store_mod.handles_stale, self.store.conn, self.handles_stale_blocks)
        if stale and self._handles_stale_steps % 100 == 0:
            logger.warning("handle directory is stale: handle events since height %s are not in the snapshot "
                           "at %s; /privacy marks it stale",
                           self.store.meta("handles_pending_height") or self.store.meta("handles_changed_height"),
                           self.store.meta("handles_height"))
        self._handles_stale_steps = self._handles_stale_steps + 1 if stale else 0

    async def _check_sizes(self, height: int) -> None:
        try:
            notes = varint_field(await self.rpc.abci_query(NOTE_TREE_QUERY, height=height), 1)
            ids = varint_field(await self.rpc.abci_query(IDENTITY_TREE_QUERY, height=height), 1)
            stakes = varint_field(await self.rpc.abci_query(STAKE_TREE_QUERY, height=height), 1)
            nfs = varint_field(await self.rpc.abci_query(STAKE_NF_TREE_QUERY, STAKE_NF_TREE_REQUEST, height=height), 2)
            debt = proto_fields(await self.rpc.abci_query(DEBT_TREE_QUERY, DEBT_TREE_REQUEST, height=height))
            dsize = (debt.get(2) or [0])[-1]
            droot = (debt.get(3) or [b""])[-1]
            window, clear_before = (debt.get(4) or [0])[-1], (debt.get(5) or [0])[-1]
        except (RPCError, ValueError, IndexError) as exc:
            # State at an old height may be pruned while catching up; the
            # check resumes once the indexer reaches heights the node keeps.
            # A WARNING all the same: while it is skipped, missing history
            # (genesis-imported notes, a late start) goes unnoticed. The
            # first skip of a run and every 100th after it.
            if self._size_skips % 100 == 0:
                logger.warning("tree size check at %d skipped (%d in a row): %s; the index is not being "
                               "compared with the chain's tree sizes", height, self._size_skips + 1, exc)
            self._size_skips += 1
            return
        if self._size_skips:
            logger.info("tree size check resumed at %d after %d skipped", height, self._size_skips)
            self._size_skips = 0
        have_notes, have_ids, _ = await asyncio.to_thread(self.store.counts)
        have_stakes, _ = await asyncio.to_thread(self.store.stake_counts)
        have_nfs = await asyncio.to_thread(self.store.stake_nf_size)
        have_dsize = await asyncio.to_thread(self.store.debt_size)
        if (notes, ids, stakes, nfs, dsize) != (have_notes, have_ids, have_stakes, have_nfs, have_dsize):
            self._halt(
                f"at height {height} the chain holds {notes} notes, {ids} identity leaves, {stakes} stake notes, a "
                f"stake nullifier tree of {nfs} leaves and a slash debt tree of {dsize}, the index {have_notes}, "
                f"{have_ids}, {have_stakes}, {have_nfs} and {have_dsize}: history before the start height (or at "
                f"genesis) is missing"
            )
        # The debt root the last row event named (the empty root before any)
        # is the chain's: rows are only written in BeginBlock, so nothing
        # after the event changed it within its block.
        last_write = await asyncio.to_thread(self.store.debt_root)
        have_droot = last_write[0] if last_write else DEBT_EMPTY_ROOT.to_bytes(32, "big")
        if droot != have_droot:
            self._halt(f"at height {height} the chain's slash debt root is {droot.hex()}, the index's "
                       f"{have_droot.hex()} (its last debt row event): history is missing")
        # What a wallet clearing a label needs besides the rows: the chain's
        # window and clear_before (block time - window) at this height.
        for k, v in (("debt_window_seconds", window), ("debt_clear_before", clear_before),
                     ("debt_checked_height", height)):
            await asyncio.to_thread(self.store.set_meta, k, str(v))
        # Only now are this batch's pages final: the API marks a page
        # immutable only up to here (audit-5 L6).
        await asyncio.to_thread(self.store.set_meta, "verified_height", str(height))

    async def run(self, stop: asyncio.Event | None = None, poll_seconds: float = 2.0) -> None:
        stop = stop or asyncio.Event()
        backoff = poll_seconds
        prepared = False
        while not stop.is_set():
            try:
                if not prepared:
                    await self.prepare()
                    prepared = True
                    logger.info("privacy indexer from height %d (tip %d)", self.next_height, self.tip)
                n = await self.step()
                backoff = poll_seconds
                if n and self.next_height <= self.tip:
                    continue  # catching up: no pause
            except Halted:
                return
            except (RPCError, KeyError, ValueError) as exc:
                # Prepare again before going on: the RPC that failed may now
                # be another node (or another chain) behind the same URL.
                prepared = False
                logger.warning("privacy indexer: %s; retrying in %.0fs", exc, backoff)
                backoff = min(backoff * 2, 60)
            except Exception:
                prepared = False
                logger.exception("privacy indexer: unexpected failure; retrying in %.0fs", backoff)
                backoff = min(backoff * 2, 60)
            try:
                await asyncio.wait_for(stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass


def from_config() -> Indexer:
    return Indexer(
        Store(config.INDEX_DB),
        CometRPC(config.INDEXER_RPC_URL, timeout=config.INDEXER_RPC_TIMEOUT),
        start_height=config.INDEXER_START_HEIGHT,
        batch=config.INDEXER_BATCH,
        concurrency=config.INDEXER_CONCURRENCY,
        handles_limit=config.HANDLES_QUERY_LIMIT,
        handles_max_age=config.HANDLES_MAX_AGE_SECONDS,
        handles_max=config.HANDLES_MAX_ENTRIES,
        handles_min_blocks=config.HANDLES_MIN_REFRESH_BLOCKS,
        handles_stale_blocks=config.HANDLES_STALE_BLOCKS,
    )


async def _main() -> None:
    idx = from_config()
    try:
        await idx.run(poll_seconds=config.INDEXER_POLL_SECONDS)
    finally:
        await idx.rpc.close()
    if idx.halted:
        raise SystemExit(f"halted: {idx.halted}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(_main())
