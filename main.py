"""earth network backend: gas grants and the privacy indexer.

Gas grants fund a new human's first transaction (routers/gas.py). The privacy
indexer follows the chain into a SQLite index of the shielded pool's public
data (services/privacy) and serves it as full-range streams for wallets to
sync (routers/privacy.py). Either can run without the other: GAS_ENABLED,
INDEXER_ENABLED.
"""
import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware

import config
from routers import gas, privacy
from services import chain
from services.bodylimit import BodyLimit
from services.privacygate import PrivacyGate

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
# httpx logs every request at INFO; the indexer makes several a second.
logging.getLogger("httpx").setLevel(logging.WARNING)

app = FastAPI(title="earth network backend", version="3.0.0")
app.add_middleware(GZipMiddleware, minimum_size=1024)
# Outside GZip: a /privacy response holds its slot until its last
# compressed byte is sent.
app.add_middleware(PrivacyGate)
# Added last, so outermost: an oversized body is refused before any other
# layer, or FastAPI's JSON parsing, reads it.
app.add_middleware(BodyLimit)
if config.GAS_ENABLED:
    app.include_router(gas.router)
app.include_router(privacy.router)

_stop = asyncio.Event()
_indexer_task: asyncio.Task | None = None
_indexer = None
_known_dsc_task: asyncio.Task | None = None


@app.on_event("startup")
async def startup() -> None:
    global _indexer_task, _indexer, _known_dsc_task
    if config.GAS_ENABLED:
        chain.init()
        from services import knowndsc

        _known_dsc_task = asyncio.create_task(knowndsc.run(_stop))
    if config.INDEXER_ENABLED:
        from services.privacy import indexer

        _indexer = indexer.from_config()
        _indexer_task = asyncio.create_task(_indexer.run(_stop, poll_seconds=config.INDEXER_POLL_SECONDS))


@app.on_event("shutdown")
async def shutdown() -> None:
    _stop.set()
    if _known_dsc_task is not None:
        await _known_dsc_task
    if _indexer_task is not None:
        await _indexer_task
        await _indexer.rpc.close()
        _indexer.store.close()


@app.get("/health")
def health():
    """Reports the hot wallet's balance — the thing that silently stops onboarding.

    When this runs dry every grant fails: the registration checks out and the
    shield does not. Worth alerting on.
    """
    if not config.GAS_ENABLED:
        return {"status": "ok", "gas": "disabled"}
    try:
        remaining = chain.balance()
    except Exception:
        # Logged, not returned. This endpoint is reachable by anyone who can
        # reach the service, and a cosmpy exception carries the node URL and
        # internals that are nobody else's business.
        logger.exception("health check could not read the hot wallet balance")
        return {"status": "degraded"}
    return {
        "status": "ok",
        "wallet": chain.wallet_address(),
        "balance_uerth": remaining,
        "dust_uerth": config.DUST_UERTH,
        "grants_remaining": remaining // config.DUST_UERTH if config.DUST_UERTH else 0,
    }
