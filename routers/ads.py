"""Ads for gas.

A new human has no ERTH and no on-chain account, so they cannot make their first
transaction — including the registration that would earn them ERTH. This closes
that loop without a faucet anyone can drain: watch a rewarded ad, and Google's
signed callback buys you enough dust to transact.

The ad is the Sybil cost. It is paid in attention rather than in ERTH, and it
pays for itself.
"""
import logging

from fastapi import APIRouter, Request

import config
from services import chain, replay, ssv

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/ads-callback", summary="AdMob Server-Side Verification callback")
async def ads_callback(request: Request):
    """Grants dust to the address in `custom_data` once an ad view is verified.

    Called by Google, not by the app. Returns 200 with a status body either way —
    AdMob retries non-2xx, and a retry cannot help any of the rejections here.
    """
    # The raw query string, not request.query_params: the signature covers the
    # exact bytes in the exact order Google sent them.
    query_string = request.scope.get("query_string", b"").decode("utf-8")
    params = dict(request.query_params)

    address = (params.get("custom_data") or "").strip()
    transaction_id = params.get("transaction_id") or ""
    signature = params.get("signature") or ""
    key_id = params.get("key_id") or ""
    ad_unit = params.get("ad_unit") or ""

    if not all([address, transaction_id, signature, key_id]):
        return {"status": "error", "message": "missing parameters"}

    # Google sends the bare numeric id, not the full ca-app-pub form.
    if config.ADMOB_AD_UNIT_ID:
        expected = config.ADMOB_AD_UNIT_ID.rsplit("/", 1)[-1]
        if ad_unit and ad_unit != expected:
            logger.warning("ad unit %s is not %s", ad_unit, expected)
            return {"status": "error", "message": "unexpected ad unit"}

    if not ssv.verify(query_string, signature, key_id, await ssv.public_keys()):
        return {"status": "error", "message": "invalid signature"}

    # Claim before sending. The insert is atomic, so two concurrent deliveries of
    # the same callback cannot both reach the chain.
    if not replay.claim(transaction_id, address):
        logger.info("replayed transaction_id %s", transaction_id)
        return {"status": "error", "message": "already granted"}

    try:
        tx_hash = await chain.send_dust(address)
    except Exception as exc:
        # Give the id back: the user watched an ad and got nothing, and should be
        # able to try again rather than have it silently consumed.
        replay.release(transaction_id)
        logger.exception("dust send to %s failed", address)
        return {"status": "error", "message": str(exc)}

    logger.info("granted %d%s to %s (tx %s)", config.DUST_UERTH, config.EARTH_DENOM, address, tx_hash)
    return {"status": "success", "tx_hash": tx_hash}
