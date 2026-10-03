"""The Document Signers the chain has already registered passports from.

/gas/register keeps a reserved lane in the gas-check queue (gascheck) for a
request whose proof names one of these: x/personhood's RegCountByDsc keys
(prefix "regs_by_dsc", key = the 32-byte DSC commitment, value = live
registrations, removed at zero), read whole with one store subspace query
over CometBFT RPC every KNOWN_DSC_REFRESH_SECONDS. Junk with random public
signals does not name one; a flood would have to copy a real signer's
commitment off the chain to compete for the lane, and still pays the
per-client limits.

A signer's first passport is not in the set and goes through the ordinary
lane, which only fills under a flood. If the query fails the last set is
kept; before the first success the set is empty and the lane unused.
"""
import asyncio
import logging

import config
from services.privacy.rpc import CometRPC, RPCError, proto_fields

logger = logging.getLogger(__name__)

STORE_PREFIX = b"regs_by_dsc"
SUBSPACE_PATH = "/store/personhood/subspace"

_known: frozenset[bytes] = frozenset()


def is_known(dsc_key: bytes) -> bool:
    return dsc_key in _known


def set_known(keys) -> None:
    global _known
    _known = frozenset(keys)


def size() -> int:
    return len(_known)


def parse_pairs(value: bytes) -> set[bytes]:
    """DSC commitments with a non-zero count, from a store subspace answer (kv.Pairs)."""
    out = set()
    for pair in proto_fields(value).get(1, []):
        f = proto_fields(pair)
        key = (f.get(1) or [b""])[-1]
        count = (f.get(2) or [b""])[-1]
        if not key.startswith(STORE_PREFIX):
            continue
        dsc = bytes(key[len(STORE_PREFIX):])
        if len(dsc) != 32:
            continue
        if len(count) == 8 and int.from_bytes(count, "big") == 0:
            continue
        out.add(dsc)
    return out


async def refresh(rpc: CometRPC | None = None) -> int:
    """Reads the set from the chain. Returns its size; raises RPCError, ValueError."""
    own = rpc is None
    rpc = rpc or CometRPC(config.EARTH_RPC_URL, timeout=config.CHAIN_HTTP_TIMEOUT)
    try:
        value = await rpc.abci_query(SUBSPACE_PATH, STORE_PREFIX)
    finally:
        if own:
            await rpc.close()
    keys = parse_pairs(value)
    set_known(keys)
    return len(keys)


async def run(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            n = await refresh()
            logger.info("known DSC set: %d signers", n)
        except (RPCError, ValueError, IndexError) as exc:
            logger.warning("known DSC set not refreshed (keeping %d): %s", len(_known), exc)
        except Exception:
            logger.exception("known DSC set not refreshed (keeping %d)", len(_known))
        try:
            await asyncio.wait_for(stop.wait(), timeout=config.KNOWN_DSC_REFRESH_SECONDS)
        except asyncio.TimeoutError:
            pass


def reset() -> None:
    set_known(())
