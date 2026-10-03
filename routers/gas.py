"""Gas for new humans, on proof of the registration they are about to make.

A new human has no ERTH, so they cannot make their first transaction — the
registration that would earn them ERTH. On the shielded chain a registration
is an unsigned private tx that pays its fee from a shielded note, so what a
new human needs is a note:

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml?, ciphertext_erth?,
                           affiliate?, pc_gas, ciphertext_gas?}

takes the registration the app is about to broadcast, asks the chain's own
checks whether it would be accepted (`earthd gas-check registration`,
services/gascheck), and if so shields DUST_UERTH from the hot wallet into a
note to pc_gas — once per passport per month, keyed on the passport nullifier,
which the registration makes public anyway. The app then broadcasts
MsgRegister and pays its fee from that note; the registration reward pays
every later fee. The backend stores only the passport key, never pc_gas or
anything else that names the note, and the note's spend is unlinkable to it.

/gas/human is gone: it paid an address the chain counted as a human, and
nothing on chain links an address to a registration any more. /gas/transparent
(a membership-proof bank send) and the device-attestation grants (/gas/ios,
/gas/android, /gas/challenge) are gone too: /gas/register is the only grant.

Grant endpoints answer with {status, message, tx_hash?} and a status code the
app can act on: 200 sent, 202 broadcast but unresolved, 4xx the request cannot
succeed as sent, 5xx try again later.
"""
import base64
import binascii
import logging

import bech32
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import config
import time

from services import chain, gascheck, replay, shielded_msg
from services.zk import privacy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gas")

# Registration grant ids: passport:<nullifier hex>:<YYYY-MM>.
PASSPORT_PREFIX = "passport:"


class RegisterGrant(BaseModel):
    # MsgRegister's own fields, bytes as standard base64 (proto JSON), except
    # its fee bundle, which the app proves only once it holds the gas note.
    proof: str
    public_signals: list[str]
    signature_algorithm: str
    dsc_der: str
    idc: str
    pc_anml: str
    pc_erth: str
    ciphertext_anml: str = ""
    ciphertext_erth: str = ""
    affiliate: str = ""
    # Where the gas goes: the pc of a note the app will spend MsgRegister's
    # fee from, and optionally that note encrypted to itself.
    pc_gas: str
    ciphertext_gas: str = ""


def _reply(status_code: int, status: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"status": status, "message": message, **extra})


def _valid_address(address: str) -> bool:
    hrp, data = bech32.bech32_decode(address)
    return hrp == config.EARTH_PREFIX and data is not None


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _field(value: str) -> bytes:
    """A 32-byte canonical field element, base64, as the chain requires of a pc or idc."""
    raw = _b64(value)
    privacy.field_from_bytes(raw)  # raises ValueError
    return raw


@router.post("/register", summary="Fund a fee note for a registration the chain would accept")
async def register(body: RegisterGrant):
    try:
        for name in ("proof", "dsc_der", "ciphertext_anml", "ciphertext_erth"):
            _b64(getattr(body, name))
        for name in ("idc", "pc_anml", "pc_erth"):
            _field(getattr(body, name))
        pc_gas = _field(body.pc_gas)
        ciphertext_gas = _b64(body.ciphertext_gas)
    except (binascii.Error, ValueError):
        return _reply(400, "error", "proof, dsc_der and ciphertexts must be base64; idc and pcs 32-byte field elements")
    if len(ciphertext_gas) > shielded_msg.MAX_CIPHERTEXT_BYTES:
        return _reply(400, "error", f"ciphertext_gas exceeds {shielded_msg.MAX_CIPHERTEXT_BYTES} bytes")
    affiliate = body.affiliate.strip()
    if affiliate and not _valid_address(affiliate):
        return _reply(400, "error", "affiliate is not an earth address")
    # MsgRegister in proto JSON, without its fee bundle (gas-check does not
    # look at it): bytes fields are standard base64, exactly as the app holds
    # them.
    msg = {
        "proof": body.proof,
        "public_signals": body.public_signals,
        "signature_algorithm": body.signature_algorithm,
        "dsc_der": body.dsc_der,
        "idc": body.idc,
        "pc_anml": body.pc_anml,
        "ciphertext_anml": body.ciphertext_anml,
        "pc_erth": body.pc_erth,
        "ciphertext_erth": body.ciphertext_erth,
        "affiliate": affiliate,
    }
    try:
        verdict = await gascheck.registration(msg)
    except gascheck.Unavailable as exc:
        logger.error("registration check unavailable: %s", exc)
        return _reply(503, "error", "verification is unavailable; try again shortly")
    if not verdict.get("ok"):
        # The chain's own reason — "passport expired", "daily cap reached" —
        # is what the user needs, and it says nothing they did not send.
        logger.info("registration check refused: %s", verdict.get("error"))
        return _reply(403, "error", f"the chain would not accept this registration: {verdict.get('error')}")
    month = time.strftime("%Y-%m", time.gmtime())
    return await _grant_note(f"{PASSPORT_PREFIX}{verdict['nullifier']}:{month}", pc_gas, ciphertext_gas)


async def _grant_note(grant_id: str, pc: bytes, ciphertext: bytes) -> JSONResponse:
    """Claims grant_id, then shields the dust to pc. Claimed under its id alone, no address.

    Claim before sending: the insert is atomic, so two concurrent requests with
    the same id cannot both reach the chain.
    """
    try:
        claimed = replay.claim(grant_id, prefix=PASSPORT_PREFIX, max_per_day=config.REGISTER_GRANT_MAX_PER_DAY)
    except replay.LimitReached as exc:
        logger.warning("%s payout limit reached; refusing a registration grant", exc)
        return _reply(429, "error", "free gas limit reached; try again tomorrow")
    if not claimed:
        return _reply(409, "error", "already granted")

    try:
        tx_hash = await chain.shield_dust(pc, ciphertext)
    except chain.SendUnresolved as exc:
        # Broadcast, outcome unknown. The id stays claimed: a tx still in a
        # mempool will land, and releasing would let it be paid twice.
        logger.error("gas note shield is unresolved: %s", exc)
        return _reply(202, "pending", "gas is on its way", tx_hash=exc.tx_hash)
    except Exception:
        replay.release(grant_id)
        logger.exception("gas note shield failed")
        return _reply(502, "error", "the grant could not be sent; try again")

    # Logged without the pc or the passport: the tx is public, the link from
    # this passport to this note need not be kept here as well.
    logger.info("shielded %d%s as a registration gas note (tx %s)", config.DUST_UERTH, config.EARTH_DENOM, tx_hash)
    return _reply(200, "success", "gas note sent", tx_hash=tx_hash)
