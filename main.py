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
from fastapi.responses import JSONResponse

import config
from routers import circuits, gas, privacy
from services import chain
from services.bodylimit import BodyLimit
from services.privacygate import PrivacyGate

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
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
app.include_router(circuits.router)

_stop = asyncio.Event()
_indexer_task: asyncio.Task | None = None
_indexer = None
_known_dsc_task: asyncio.Task | None = None
_health_task: asyncio.Task | None = None


@app.on_event("startup")
async def startup() -> None:
    global _indexer_task, _indexer, _known_dsc_task, _health_task
    if config.GAS_ENABLED:
        chain.init()
        from services import health as health_mod, knowndsc

        _known_dsc_task = asyncio.create_task(knowndsc.run(_stop))
        _health_task = asyncio.create_task(health_mod.run(_stop))
    if config.INDEXER_ENABLED:
        from services.privacy import indexer

        _indexer = indexer.from_config()
        _indexer_task = asyncio.create_task(_indexer.run(_stop, poll_seconds=config.INDEXER_POLL_SECONDS))


@app.on_event("shutdown")
async def shutdown() -> None:
    _stop.set()
    if _known_dsc_task is not None:
        await _known_dsc_task
    if _health_task is not None:
        await _health_task
    if _indexer_task is not None:
        await _indexer_task
        await _indexer.rpc.close()
        _indexer.store.close()


@app.get("/health")
def health():
    """Reports the hot wallet's balance — the thing that silently stops onboarding.

    When this runs dry every grant fails: the registration checks out and the
    shield does not. Worth alerting on. The balance is read in the
    background every HEALTH_REFRESH_SECONDS (services/health); a request
    never reaches the LCD, and the answer is cacheable for as long.
    """
    if not config.GAS_ENABLED:
        body = {"status": "ok", "gas": "disabled"}
    else:
        from services import health as health_mod

        body = health_mod.snapshot()
    return JSONResponse(body, headers={"Cache-Control": f"public, max-age={int(config.HEALTH_REFRESH_SECONDS)}"})
