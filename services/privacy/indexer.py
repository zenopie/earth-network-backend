"""Follows the chain block by block into the privacy index.

    python -m services.privacy.indexer          # standalone, until interrupted

or, inside the API process, started by main.py when INDEXER_ENABLED.

CometBFT finality is instant: a committed block is never reverted, so the
indexer only ever moves forward and never rolls back. What it does guard
against is the RPC pointing at a different chain than the one indexed (a
relaunch under the same chain id, a misconfigured URL): the chain id and the
hash of the last indexed block are checked on every start, and a mismatch
halts the indexer — wipe INDEX_DB to start over.

Blocks are fetched in batches (block_results concurrently, block times and
hashes from /blockchain) and applied strictly in order, one SQLite
transaction each; see store.py for what applying checks. After each batch
the indexed tree sizes are compared with the chain's own (an abci_query of
x/shielded Tree and x/personhood IdentityTree at that height). That catches
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
        last = self.store.last_height()
        if last:
            metas = await self.rpc.block_metas(last, last)
            if last in metas and metas[last][0] != self.store.block_hash(last):
                self._halt(f"block {last} hash is {metas[last][0]} on the RPC, {self.store.block_hash(last)} in the index: a different chain")
            self.next_height = last + 1
        else:
            start = self.start_height or st["earliest_height"]
            if start < st["earliest_height"]:
                self._halt(f"start height {start} is below the node's earliest block {st['earliest_height']}; use a full-history node (rpc.erth.network)")
            self.next_height = start

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
            block_hash, t = metas[h]
            try:
                delta = parse_block(h, t, block_hash, res)
                await asyncio.to_thread(self.store.apply, delta)
            except (EventError, Inconsistent) as exc:
                self._halt(f"block {h}: {exc}")
            self.next_height = h + 1
            applied += 1
        if self.check_sizes:
            await self._check_sizes(heights[-1])
        return applied

    async def _check_sizes(self, height: int) -> None:
        try:
            notes = varint_field(await self.rpc.abci_query(NOTE_TREE_QUERY, height=height), 1)
            ids = varint_field(await self.rpc.abci_query(IDENTITY_TREE_QUERY, height=height), 1)
        except (RPCError, ValueError, IndexError) as exc:
            # State at an old height may be pruned while catching up; the
            # check resumes once the indexer reaches heights the node keeps.
            logger.debug("tree size check at %d skipped: %s", height, exc)
            return
        have_notes, have_ids, _ = await asyncio.to_thread(self.store.counts)
        if (notes, ids) != (have_notes, have_ids):
            self._halt(
                f"at height {height} the chain holds {notes} notes and {ids} identity leaves, the index "
                f"{have_notes} and {have_ids}: history before the start height (or at genesis) is missing"
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
                logger.warning("privacy indexer: %s; retrying in %.0fs", exc, backoff)
                backoff = min(backoff * 2, 60)
            except Exception:
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
