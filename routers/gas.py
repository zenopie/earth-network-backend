"""Gas for new humans, on proof of the registration they are about to make.

A new human has no ERTH, so they cannot make their first transaction — the
registration that would earn them ERTH. On the shielded chain a registration
is an unsigned private tx that pays its fee from a shielded note, so what a
new human needs is a note:

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml, ciphertext_erth,
                           affiliate?, pc_gas, ciphertext_gas}

Every ciphertext is a note's amount-blind v2 ciphertext (zk/privacy
EncryptBlindNote), exactly 177 bytes, as the chain requires of every note it
mints: ciphertext_anml / ciphertext_erth exactly as in MsgRegister (the proof's
binding covers them), ciphertext_gas the gas note's own.

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
import calendar
import logging
import re
import time
from typing import Annotated

import bech32
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints

import config

from services import chain, gascheck, knowndsc, ratelimit, replay, shielded_msg
from services.zk import privacy
from services.zk.poseidon2 import P

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gas")

# Registration grant ids: passport:<nullifier hex>:<YYYY-MM>.
PASSPORT_PREFIX = "passport:"


def _b64_len(n: int) -> int:
    return 4 * ((n + 2) // 3)


# Field caps, checked while the body is validated: loose upper bounds that
# keep any one field (and the decoded model) small. The exact bounds the
# chain enforces are _precheck's, which answers 400 with a reason.
_SHORT = Annotated[str, StringConstraints(max_length=2048)]
_SIGNAL = Annotated[str, StringConstraints(max_length=128)]


class RegisterGrant(BaseModel):
    # MsgRegister's own fields, bytes as standard base64 (proto JSON), except
    # its fee bundle, which the app proves only once it holds the gas note.
    proof: Annotated[str, StringConstraints(max_length=_b64_len(32 * 1024) + 64)]
    public_signals: list[_SIGNAL] = Field(max_length=64)
    signature_algorithm: Annotated[str, StringConstraints(max_length=256)]
    dsc_der: Annotated[str, StringConstraints(max_length=_b64_len(8 * 1024) + 64)]
    idc: _SHORT
    pc_anml: _SHORT
    pc_erth: _SHORT
    ciphertext_anml: _SHORT
    ciphertext_erth: _SHORT
    affiliate: Annotated[str, StringConstraints(max_length=256)] = ""
    # Where the gas goes: the pc of a note the app will spend MsgRegister's
    # fee from, and that note's amount-blind v2 ciphertext (MsgShield's,
    # required).
    pc_gas: _SHORT
    ciphertext_gas: _SHORT


_HEX_RUN = re.compile(r"(0x)?[0-9a-fA-F]{16,}")


def _coarse(reason) -> str:
    """A refusal reason for the log: hex runs (nullifiers, keys, hashes) cut out, length bounded."""
    return _HEX_RUN.sub("<hex>", str(reason))[:120]


def _reply(status_code: int, status: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"status": status, "message": message, **extra})


def _valid_address(address: str) -> bool:
    """An earth address in its canonical (lowercase) encoding, as the chain's
    personhood canonicalBytes requires of MsgRegister.affiliate."""
    hrp, data = bech32.bech32_decode(address)
    return hrp == config.EARTH_PREFIX and data is not None and bech32.bech32_encode(hrp, data) == address


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _field(value: str) -> bytes:
    """A 32-byte canonical field element, base64, as the chain requires of a pc or idc."""
    raw = _b64(value)
    privacy.field_from_bytes(raw)  # raises ValueError
    return raw


# Bounds MsgRegister.ValidateBasic enforces (x/personhood/types/msgs.go,
# x/shielded/types/keys.go); checked here so junk never reaches gas-check.
MAX_PUBLIC_SIGNALS = 16
MAX_PROOF_BYTES = 32 * 1024
MAX_DSC_DER_BYTES = 8 * 1024
MAX_ADDRESS_BYTES = 128
MAX_SIGNATURE_ALGORITHM_BYTES = 64
# Wall clock against block time: allow a little more skew than the chain so a
# date right at the edge is the chain's call, not ours.
_DATE_SLACK_SECONDS = 600


def _signal(s: str) -> int:
    """personhood ParseSignal: a decimal canonical field element."""
    if not (0 < len(s) <= 78 and s.isascii() and s.isdigit()):
        raise ValueError("not a decimal")
    v = int(s)
    if v >= P:
        raise ValueError("not canonical")
    return v


def _yymmdd_unix(v: int) -> int:
    """The chain's yymmddToUnix: a YYMMDD current_date at 00:00 UTC, years 2000-2099."""
    if v > 999999:
        raise ValueError("current_date is not a YYMMDD value")
    yy, mm, dd = v // 10000, (v // 100) % 100, v % 100
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        raise ValueError("current_date has an invalid month or day")
    # Go's time.Date normalises an out-of-range day (Feb 31 -> Mar 3); so does this.
    return calendar.timegm((2000 + yy, mm, 1, 0, 0, 0)) + (dd - 1) * 86400


class _Refuse(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _precheck(body: RegisterGrant) -> tuple[str, str, bytes, bytes, str, bytes | None]:
    """Everything about a registration that needs no gas-check, cheapest first.

    Returns (passport nullifier hex, grant id, pc_gas, ciphertext_gas,
    affiliate, DSC commitment or None) or raises _Refuse.
    Every value checked here is a public input the chain then verifies the
    proof against, so refusing on it early never refuses what the chain would
    take — it only stops a replay, a stale or mis-bound proof, or junk from
    costing a proof verification.
    """
    try:
        proof = _b64(body.proof)
        dsc_der = _b64(body.dsc_der)
        ciphertexts = [_b64(body.ciphertext_anml), _b64(body.ciphertext_erth)]
        idc, pc_anml, pc_erth = (privacy.field_from_bytes(_b64(getattr(body, n))) for n in ("idc", "pc_anml", "pc_erth"))
        pc_gas = _field(body.pc_gas)
        ciphertext_gas = _b64(body.ciphertext_gas)
    except (binascii.Error, ValueError):
        raise _Refuse(400, "proof, dsc_der and ciphertexts must be base64; idc and pcs 32-byte field elements")
    if not 0 < len(proof) <= MAX_PROOF_BYTES:
        raise _Refuse(400, f"proof must be 1..{MAX_PROOF_BYTES} bytes")
    if not 0 < len(dsc_der) <= MAX_DSC_DER_BYTES:
        raise _Refuse(400, f"dsc_der must be 1..{MAX_DSC_DER_BYTES} bytes")
    if any(len(c) != shielded_msg.BLIND_CIPHERTEXT_BYTES for c in ciphertexts + [ciphertext_gas]):
        raise _Refuse(400, f"each ciphertext must be an amount-blind v2 ciphertext of exactly "
                           f"{shielded_msg.BLIND_CIPHERTEXT_BYTES} bytes")
    if not 0 < len(body.signature_algorithm.encode()) <= MAX_SIGNATURE_ALGORITHM_BYTES:
        raise _Refuse(400, "signature_algorithm is missing or too long")
    affiliate = body.affiliate.strip()
    affiliate_field = 0
    if affiliate:
        if len(affiliate) > MAX_ADDRESS_BYTES or not _valid_address(affiliate):
            raise _Refuse(400, "affiliate is not an earth address")
        _, data = bech32.bech32_decode(affiliate)
        affiliate_field = privacy.bytes_field(bytes(bech32.convertbits(data, 5, 8, False)))

    n = len(body.public_signals)
    if not 0 < n <= MAX_PUBLIC_SIGNALS:
        raise _Refuse(400, f"need 1..{MAX_PUBLIC_SIGNALS} public signals")
    try:
        signals = [_signal(x) for x in body.public_signals]
    except ValueError:
        raise _Refuse(400, "public signals must be canonical decimal field elements")
    if max(config.PASSPORT_NULLIFIER_INDEX, config.PASSPORT_ADDRESS_INDEX, config.PASSPORT_CURRENT_DATE_INDEX) >= n:
        raise _Refuse(400, "too few public signals for a passport proof")

    # The binding: the proof's address input must be this msg's idc, pcs,
    # note ciphertexts (and affiliate). Someone replaying another registration's proof with
    # notes of their own fails here, as on chain.
    if signals[config.PASSPORT_ADDRESS_INDEX] != privacy.registration_binding(idc, pc_anml, ciphertexts[0], pc_erth, ciphertexts[1], affiliate_field):
        raise _Refuse(400, "proof is bound to a different identity and notes than this registration names")

    try:
        proof_unix = _yymmdd_unix(signals[config.PASSPORT_CURRENT_DATE_INDEX])
    except ValueError as exc:
        raise _Refuse(400, str(exc))
    if abs(time.time() - proof_unix) > config.PASSPORT_DATE_MAX_SKEW_SECONDS + _DATE_SLACK_SECONDS:
        raise _Refuse(400, "current_date is too far from today; prove again")

    nullifier = privacy.field_bytes(signals[config.PASSPORT_NULLIFIER_INDEX]).hex()
    month = time.strftime("%Y-%m", time.gmtime())
    # Not refused when absent: whether a DSC is required is the chain's call.
    dsc = privacy.field_bytes(signals[config.PASSPORT_DSC_KEY_INDEX]) if config.PASSPORT_DSC_KEY_INDEX < n else None
    return nullifier, f"{PASSPORT_PREFIX}{nullifier}:{month}", pc_gas, ciphertext_gas, affiliate, dsc


@router.post("/register", summary="Fund a fee note for a registration the chain would accept")
async def register(body: RegisterGrant, request: Request):
    client = ratelimit.client_key(ratelimit.client_ip(request))
    if not ratelimit.allow(client):
        return _reply(429, "error", "too many requests; try again later")
    try:
        nullifier, grant_id, pc_gas, ciphertext_gas, affiliate, dsc = _precheck(body)
    except _Refuse as exc:
        return _reply(exc.status_code, "error", str(exc))
    # Replay and cap before the check: both are a table read, the check is a
    # proof verification. claim() decides again after it, atomically.
    if replay.peek(grant_id):
        return _reply(409, "error", "already granted")
    if replay.limit_reached(PASSPORT_PREFIX, config.REGISTER_GRANT_MAX_PER_DAY):
        return _reply(429, "error", "free gas limit reached; try again tomorrow")
    # The reserved lane: a passport not yet granted (peek, above) from a
    # Document Signer the chain already holds registrations from. While the
    # refusal budget is spent, nothing else is queued at all.
    priority = dsc is not None and knowndsc.is_known(dsc)
    if not priority and ratelimit.shedding():
        return _reply(429, "error", "too many failed registrations right now; try again in a minute")

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
        with ratelimit.one_at_a_time(client):
            verdict = await gascheck.registration(msg, priority=priority)
    except ratelimit.Busy:
        return _reply(429, "error", "a check for this client is already running; wait for it")
    except gascheck.Unavailable as exc:
        logger.error("registration check unavailable: %s", _coarse(exc))
        return _reply(503, "error", "verification is unavailable; try again shortly")
    if not verdict.get("ok"):
        ratelimit.note_refusal()
        # The chain's own reason — "passport expired", "daily cap reached" —
        # is what the user needs, and it says nothing they did not send. The
        # log keeps a coarse version: no hex that could be a nullifier.
        logger.info("registration check refused: %s", _coarse(verdict.get("error")))
        return _reply(403, "error", f"the chain would not accept this registration: {verdict.get('error')}")
    if verdict.get("nullifier") != nullifier:
        # gas-check read the nullifier from the chain's nullifier_index; ours
        # disagrees, so PASSPORT_NULLIFIER_INDEX does not match the chain.
        logger.error("gas-check nullifier differs from public_signals[%d]; check PASSPORT_NULLIFIER_INDEX",
                     config.PASSPORT_NULLIFIER_INDEX)
        return _reply(503, "error", "verification is unavailable; try again shortly")
    return await _grant_note(grant_id, pc_gas, ciphertext_gas)


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
        if not exc.tx_hash:
            # Nothing names a tx that could land, so nothing can be paid
            # twice: give the passport back rather than strand it for a month.
            replay.release(grant_id)
            logger.error("gas note shield failed before a tx existed: %s", exc)
            return _reply(502, "error", "the grant could not be sent; try again")
        # Broadcast, and the chain did not show it within the wait. The id
        # stays claimed: a tx still in a mempool will land, and releasing
        # would let it be paid twice. The app holds the hash and can watch for
        # it; this side keeps no record that ties it to the passport.
        logger.error("gas note shield is unresolved: %s", exc)
        return _reply(202, "pending", "gas is on its way", tx_hash=exc.tx_hash)
    except Exception as exc:
        replay.release(grant_id)
        # Not logger.exception: a cosmpy error names the tx hash.
        logger.error("gas note shield failed: %s: %s", exc.__class__.__name__, _coarse(exc))
        return _reply(502, "error", "the grant could not be sent; try again")

    # Logged without the tx hash, the pc or the passport. The registration
    # and the shield are both public; a log line naming the shield's tx at the
    # moment a passport checked out would tie the two together by timing.
    logger.info("registration gas note sent")
    return _reply(200, "success", "gas note sent", tx_hash=tx_hash)
