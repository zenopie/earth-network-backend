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
x/shielded Tree, x/personhood IdentityTree and x/shieldedstaking StakeTree at
that height). That catches
history the index never saw — notes or leaves imported at genesis, which emit
no events, or a start height past the first private tx — which events alone
cannot reveal.

Needs a node that keeps block results from the start height on
(storage.discard_abci_responses = false, the default, and no block pruning
below it).
"""
import asyncio
import logging

import config

from .events import EventError, parse_block
from .rpc import CometRPC, RPCError, varint_field
from .store import Inconsistent, Store

logger = logging.getLogger(__name__)

NOTE_TREE_QUERY = "/earth.shielded.v1.Query/Tree"  # QueryTreeResponse.tree_size = 1
IDENTITY_TREE_QUERY = "/earth.personhood.v1.Query/IdentityTree"  # QueryIdentityTreeResponse.size = 1
STAKE_TREE_QUERY = "/earth.shieldedstaking.v1.Query/StakeTree"  # QueryStakeTreeResponse.size = 1


class Halted(Exception):
    """The index cannot continue without an operator: it would diverge from the chain."""


class Indexer:
    def __init__(self, store: Store, rpc: CometRPC, *, start_height: int = 0, batch: int = 20,
                 concurrency: int = 8, check_sizes: bool = True):
        self.store = store
        self.rpc = rpc
        self.start_height = start_height
        self.batch = batch
        self._sem = asyncio.Semaphore(concurrency)
        self.check_sizes = check_sizes
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
        return applied

    async def _check_sizes(self, height: int) -> None:
        try:
            notes = varint_field(await self.rpc.abci_query(NOTE_TREE_QUERY, height=height), 1)
            ids = varint_field(await self.rpc.abci_query(IDENTITY_TREE_QUERY, height=height), 1)
            stakes = varint_field(await self.rpc.abci_query(STAKE_TREE_QUERY, height=height), 1)
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
        if (notes, ids, stakes) != (have_notes, have_ids, have_stakes):
            self._halt(
                f"at height {height} the chain holds {notes} notes, {ids} identity leaves and {stakes} stake notes, "
                f"the index {have_notes}, {have_ids} and {have_stakes}: history before the start height (or at genesis) is missing"
            )

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
