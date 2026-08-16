"""earth ads-for-gas service.

One job: turn a verified rewarded-ad view into enough ERTH for a new human to
make their first transaction. Everything else the old Secret-era backend did is
gone — registration is proved on-device and verified on-chain now, and the CSCA
trust store moved to the chain repo where it is enforced.
"""
import logging

from fastapi import FastAPI

import config
from routers import ads
from services import chain

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="earth ads-for-gas", version="1.0.0")
app.include_router(ads.router)


@app.on_event("startup")
def startup() -> None:
    chain.init()


@app.get("/health")
def health():
    """Reports the hot wallet's balance — the thing that silently stops onboarding.

    When this runs dry every ad view is wasted: the callback verifies, the id is
    consumed, and the send fails. Worth alerting on.
    """
    try:
        remaining = chain.balance()
    except Exception as exc:
        return {"status": "degraded", "error": str(exc)}
    return {
        "status": "ok",
        "wallet": chain.wallet_address(),
        "balance_uerth": remaining,
        "dust_uerth": config.DUST_UERTH,
        "grants_remaining": remaining // config.DUST_UERTH if config.DUST_UERTH else 0,
    }
