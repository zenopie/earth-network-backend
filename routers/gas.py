"""Gas for new humans, paid on proof of a genuine app install.

A new human has no ERTH and no on-chain account, so they cannot make their first
transaction — including the registration that would earn them ERTH. This closes
that loop: the app proves, through the platform's own attestation, that it is a
genuine copy running on a real device, and the backend sends enough dust to
transact. On iOS that is App Attest; on Android, hardware key attestation, which
needs no Google account or Play services and accepts any install of our signed
APK, sideloaded included.

The attestation is the Sybil cost. It cannot be produced by a script, only by
our signed app on real hardware, and the per-address and daily caps in replay
bound what one phone farming fresh addresses can take.

    POST /gas/challenge   {address}                                -> {challenge, expires_in}
    POST /gas/ios         {address, challenge, key_id, attestation} App Attest
    POST /gas/android     {address, challenge, chain}               Key Attestation

Both grant endpoints answer with {status, message, tx_hash?} and a status code
the app can act on: 200 sent, 202 broadcast but unresolved, 4xx the request
cannot succeed as sent, 5xx try again later.
"""
import base64
import binascii
import logging

import bech32
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config
from services import appattest, chain, challenges, keyattest, replay

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gas")


class ChallengeRequest(BaseModel):
    address: str


class IosGrant(BaseModel):
    address: str
    challenge: str
    key_id: str
    attestation: str


class AndroidGrant(BaseModel):
    address: str
    challenge: str
    chain: list[str]


def _reply(status_code: int, status: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"status": status, "message": message, **extra})


def _valid_address(address: str) -> bool:
    hrp, data = bech32.bech32_decode(address)
    return hrp == config.EARTH_PREFIX and data is not None


@router.post("/challenge", summary="A single-use challenge to attest over")
def challenge(body: ChallengeRequest):
    address = body.address.strip()
    if not _valid_address(address):
        return _reply(400, "error", "not an earth address")
    try:
        value = challenges.issue(address)
    except challenges.Busy:
        return _reply(503, "error", "too many requests in flight; try again shortly")
    return {"challenge": value, "expires_in": config.CHALLENGE_TTL_SECONDS}


@router.post("/ios", summary="Grant gas on an App Attest attestation")
async def ios(body: IosGrant):
    address = body.address.strip()
    digest = challenges.consume(body.challenge, address)
    if digest is None:
        return _reply(409, "error", "challenge expired or already used; start again")
    try:
        attestation = base64.b64decode(body.attestation, validate=True)
    except (binascii.Error, ValueError):
        return _reply(400, "error", "attestation is not base64")
    try:
        appattest.verify(
            attestation,
            body.key_id,
            digest,
            app_id=config.IOS_APP_ID,
            allow_development=config.APP_ATTEST_ALLOW_DEVELOPMENT,
        )
    except appattest.AttestationError as exc:
        logger.warning("App Attest refused for %s: %s", address, exc)
        return _reply(403, "error", "this device could not verify the app")
    # Keyed on the attested key: each one is a fresh Secure Enclave key, so a
    # second grant from the same attestation is a replay, whatever the challenge.
    return await _grant(f"ios:{body.key_id}", address)


@router.post("/android", summary="Grant gas on a hardware key attestation")
async def android(body: AndroidGrant):
    address = body.address.strip()
    if not config.ANDROID_SIGNING_CERT_SHA256:
        return _reply(503, "error", "Android grants are not configured on this server")
    digest = challenges.consume(body.challenge, address)
    if digest is None:
        return _reply(409, "error", "challenge expired or already used; start again")
    try:
        chain_der = [base64.b64decode(c, validate=True) for c in body.chain]
    except (binascii.Error, ValueError):
        return _reply(400, "error", "chain is not base64")
    try:
        key_hash = await keyattest.verify_async(chain_der, digest)
    except keyattest.AttestationError as exc:
        logger.warning("key attestation refused for %s: %s", address, exc)
        return _reply(403, "error", "this device could not verify the app")
    except keyattest.Unavailable as exc:
        logger.error("key attestation unavailable: %s", exc)
        return _reply(503, "error", "verification is unavailable; try again shortly")
    # Keyed on the attested key, as on iOS: a fresh hardware key per request.
    return await _grant(f"android:{key_hash.hex()}", address)


async def _grant(grant_id: str, address: str) -> JSONResponse:
    # Claim before sending. The insert is atomic, so two concurrent requests
    # with the same id cannot both reach the chain.
    try:
        claimed = replay.claim(grant_id, address)
    except replay.LimitReached as exc:
        logger.warning("%s payout limit reached; refusing %s for %s", exc, grant_id, address)
        return _reply(429, "error", "free gas limit reached; try again tomorrow")
    if not claimed:
        return _reply(409, "error", "already granted")

    try:
        tx_hash = await chain.send_dust(address)
    except chain.SendUnresolved as exc:
        # Broadcast, outcome unknown. The id stays claimed: a transaction still
        # in a mempool will land, and releasing would let it be paid twice.
        logger.error("dust send to %s is unresolved: %s", address, exc)
        return _reply(202, "pending", "gas is on its way", tx_hash=exc.tx_hash)
    except Exception:
        # The send demonstrably moved nothing. Give the id back so it does not
        # count against the address's allowance.
        replay.release(grant_id)
        logger.exception("dust send to %s failed", address)
        return _reply(502, "error", "the grant could not be sent; try again")

    logger.info("granted %d%s to %s (%s, tx %s)", config.DUST_UERTH, config.EARTH_DENOM, address, grant_id.split(":")[0], tx_hash)
    return _reply(200, "success", "gas sent", tx_hash=tx_hash)
