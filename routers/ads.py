"""Ads for gas.

A new human has no ERTH and no on-chain account, so they cannot make their first
transaction — including the registration that would earn them ERTH. This closes
that loop without a faucet anyone can drain: watch a rewarded ad, and Google's
signed callback buys you enough dust to transact.

The ad is the Sybil cost. It is paid in attention rather than in ERTH, and it
pays for itself.
"""
import logging
import time

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

    # Everything the decisions below are made on is read from the *signed*
    # prefix, and nothing is read from the full query string.
    #
    # The signature covers only what precedes `&signature=`, while Starlette's
    # QueryParams is last-wins — so `dict(request.query_params)` returns a
    # parameter appended *after* the signature in preference to the one the
    # signature actually covers. Reading the decisions from there meant a single
    # captured callback could be replayed with `&custom_data=<attacker>` and a
    # fresh `&transaction_id=` tacked on the end: the signature still verified
    # over the untouched prefix, the dust went somewhere else, the replay table
    # never saw the id it had already honoured, and the ad-unit allowlist was
    # bypassed the same way. All three checks fell to one appended parameter.
    #
    # And it is read from the prefix *as signed*, which is its decoded form.
    # Parsing the raw prefix instead let a captured callback be re-encoded into a
    # second payout: `&` and `%26` decode alike, so turning the real
    # `&transaction_id=` into `%26transaction_id%3D` and un-encoding a
    # `transaction_id=` smuggled inside the app-chosen user_id changed which id
    # the parser saw without changing a byte the signature covers.
    #
    # Duplicates within the signed prefix are refused rather than resolved.
    # Google does not send them, and picking a winner is how this class of bug
    # comes back. They are also what that smuggled parameter looks like once
    # the prefix is read the way it was signed.
    if "&signature=" not in query_string:
        return {"status": "error", "message": "missing parameters"}
    signed_items = ssv.signed_params(query_string)
    if len({name for name, _ in signed_items}) != len(signed_items):
        logger.warning("callback has duplicate signed parameters")
        return {"status": "error", "message": "duplicate parameters"}
    params = dict(signed_items)

    address = (params.get("custom_data") or "").strip()
    transaction_id = params.get("transaction_id") or ""
    ad_unit = params.get("ad_unit") or ""

    # These two are the verification inputs rather than decisions taken on
    # trust, and they sit after `&signature=` so they are not in the signed
    # prefix. A forged key_id only selects a key the signature then fails
    # against.
    signature = request.query_params.get("signature") or ""
    key_id = request.query_params.get("key_id") or ""

    if not all([address, transaction_id, signature, key_id]):
        return {"status": "error", "message": "missing parameters"}

    # Google sends the bare numeric id, not the full ca-app-pub form.
    #
    # Membership, not equality: Android and iOS have separate units for the same
    # reward and both call this endpoint. Comparing against one of them rejected
    # every callback from the other platform here, before the signature was even
    # checked — an ad watched, no dust, and nothing in the app to explain it.
    #
    # A missing ad_unit is refused rather than waved through. It used to be, via
    # `if ad_unit and ...`, which made the whole guard skippable by omitting the
    # parameter — the signature still had to verify, so it was not a bypass, but
    # a check that silently does nothing is worse than no check at all.
    if config.ADMOB_AD_UNIT_IDS and ad_unit not in config.ADMOB_AD_UNIT_IDS:
        logger.warning(
            "ad unit %r is not one of %s",
            ad_unit,
            ", ".join(sorted(config.ADMOB_AD_UNIT_IDS)),
        )
        return {"status": "error", "message": "unexpected ad unit"}

    if not ssv.verify(query_string, signature, key_id, await ssv.keys_for(key_id)):
        return {"status": "error", "message": "invalid signature"}

    # Checked after the signature, so it is Google's clock being read and not
    # the caller's. Milliseconds since the epoch.
    try:
        age = time.time() - int(params.get("timestamp") or "") / 1000
    except ValueError:
        return {"status": "error", "message": "missing parameters"}
    if age > config.SSV_MAX_AGE_SECONDS or -age > config.SSV_MAX_FUTURE_SECONDS:
        logger.warning("callback %s is outside the timestamp window (age %.0fs)", transaction_id, age)
        return {"status": "error", "message": "stale callback"}

    # Claim before sending. The insert is atomic, so two concurrent deliveries of
    # the same callback cannot both reach the chain.
    if not replay.claim(transaction_id, address):
        logger.info("replayed transaction_id %s", transaction_id)
        return {"status": "error", "message": "already granted"}

    try:
        tx_hash = await chain.send_dust(address)
    except chain.SendUnresolved as exc:
        # Broadcast, outcome unknown. The id stays claimed: a transaction that
        # is still in a mempool will land, and releasing here would let the same
        # callback — Google retries them — be paid a second time. The cost of
        # being wrong is one ad view; the cost of the other choice is paying
        # twice for it, every time the LCD is slow.
        logger.error("dust send to %s is unresolved: %s", address, exc)
        return {"status": "error", "message": "grant pending", "tx_hash": exc.tx_hash}
    except Exception:
        # The send demonstrably moved nothing — it never reached the chain, or
        # it was included and failed. Give the id back: the user watched an ad
        # and got nothing, and should be able to try again rather than have it
        # silently consumed.
        replay.release(transaction_id)
        logger.exception("dust send to %s failed", address)
        return {"status": "error", "message": "grant failed"}

    logger.info("granted %d%s to %s (tx %s)", config.DUST_UERTH, config.EARTH_DENOM, address, tx_hash)
    return {"status": "success", "tx_hash": tx_hash}
