"""The hot wallet's balance for /health, read in the background (audit-5 L3).

One task reads the balance every HEALTH_REFRESH_SECONDS and /health serves
the last reading (cacheable for as long), whatever the request rate: a
request never queries the LCD, so a flood of /health cannot exhaust the
threadpool the /privacy handlers share or load the node.
"""
import asyncio
import logging
import time

import config
from services import chain

logger = logging.getLogger(__name__)

_snapshot: dict = {"status": "starting"}


def snapshot() -> dict:
    return _snapshot


async def refresh() -> None:
    global _snapshot
    try:
        remaining = await asyncio.to_thread(chain.balance)
    except Exception:
        # Logged, not served: a cosmpy exception carries the node URL and
        # internals that are nobody else's business.
        logger.exception("health check could not read the hot wallet balance")
        _snapshot = {"status": "degraded"}
        return
    _snapshot = {
        "status": "ok",
        "wallet": chain.wallet_address(),
        "balance_uerth": remaining,
        "dust_uerth": config.DUST_UERTH,
        "grants_remaining": remaining // config.DUST_UERTH if config.DUST_UERTH else 0,
        "read_at": int(time.time()),
    }


async def run(stop: asyncio.Event) -> None:
    while not stop.is_set():
        await refresh()
        try:
            await asyncio.wait_for(stop.wait(), timeout=config.HEALTH_REFRESH_SECONDS)
        except asyncio.TimeoutError:
            pass


def reset() -> None:
    global _snapshot
    _snapshot = {"status": "starting"}
