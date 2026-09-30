"""earth gas-grant service.

One job: turn an attested request from a genuine app install into enough ERTH
for a new human to make their first transaction. Everything else the old
Secret-era backend did is gone — registration is proved on-device and verified on-chain now, and the CSCA
trust store moved to the chain repo where it is enforced.
"""
import logging

from fastapi import FastAPI

import config
from routers import gas
from services import chain

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="earth gas grants", version="2.0.0")
app.include_router(gas.router)


@app.on_event("startup")
def startup() -> None:
    chain.init()


@app.get("/health")
def health():
    """Reports the hot wallet's balance — the thing that silently stops onboarding.

    When this runs dry every grant fails: the attestation verifies and the send
    does not. Worth alerting on.
    """
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
