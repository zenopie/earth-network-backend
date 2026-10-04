"""Gas for new humans, on proof of the registration they are about to make.

A new human has no ERTH, so they cannot make their first transaction — the
registration that would earn them ERTH. On the shielded chain a registration
is an unsigned private tx that pays its fee from a shielded note, so what a
new human needs is a note:

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml, ciphertext_erth,
                           affiliate_handle?,
                           pc_gas, ciphertext_gas, pow?}
    GET  /gas/pow         the proof of work it needs now (services/pow)

Every ciphertext is a note's amount-blind v2 ciphertext (zk/privacy
EncryptBlindNote), exactly 177 bytes, as the chain requires of every note it
mints: ciphertext_anml / ciphertext_erth exactly as in MsgRegister (the proof's
binding covers them), ciphertext_gas the gas note's own.

A referral names a live handle (affiliate_handle, MsgRegister field 15),
bound into the proof as H("earth.affiliate", Bytes(handle)) (0 for none).
The chain itself mints the referrer's half as a note to the handle's address,
with an opening derived from the passport nullifier and leaf index (chain
ORCHARD_DESIGN.md section 16); the registrant's wallet makes no referral note.
affiliate_pc and affiliate_ciphertext (MsgRegister 11 and 12, removed in
audit round 5) are refused with a 400 naming them.

takes the registration the app is about to broadcast, asks the chain's own
checks whether it would be accepted (`earthd gas-check registration`,
services/gascheck), and if so shields DUST_UERTH from the hot wallet into a
note to pc_gas — once per passport in any 30 days, keyed on the passport nullifier,
which the registration makes public anyway. The app then broadcasts
MsgRegister and pays its fee from that note; the registration reward pays
every later fee. The backend stores only the passport key, never pc_gas or
anything else that names the note, and the note's spend is unlinkable to it.

/gas/human is gone: it paid an address the chain counted as a human, and
nothing on chain links an address to a registration any more. /gas/transparent
(a membership-proof bank send) and the device-attestation grants (/gas/ios,
/gas/android, /gas/challenge) are gone too: /gas/register is the only grant.

Grant endpoints answer with {status, message, tx_hash?} and a status code the
app can act on: 200 sent, 202 broadcast but unresolved, 428 attach (or
redo) a proof of work, other 4xx the request cannot succeed as sent, 5xx try
again later.
"""
import base64
import binascii
import calendar
import logging
import re
import time
from typing import Annotated, Any

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints, ValidationError
from pydantic.json_schema import SkipJsonSchema

import config

from services import chain, dsccommit, gascheck, knowndsc, pow, ratelimit, replay, shielded_msg
from services.privacy import handles
from services.zk import privacy
from services.zk.poseidon2 import P

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gas")

# Registration grant ids: passport:<nullifier hex>:<YYYY-MM-DD>, at most one
# per passport in any GRANT_ONCE_PER_SECONDS (ids from before this change end
# in :<YYYY-MM>; they share the passport's prefix and count the same).
PASSPORT_PREFIX = "passport:"
# The replay kind of a grant for a switch (a passport already registered
# moving to a new identity): capped apart from first registrations.
SWITCH = "switch"
GRANT_ONCE_PER_SECONDS = 30 * 86400


def _b64_len(n: int) -> int:
    return 4 * ((n + 2) // 3)


# Field caps, checked while the body is validated: loose upper bounds that
# keep any one field (and the decoded model) small. The exact bounds the
# chain enforces are _precheck's, which answers 400 with a reason.
_SHORT = Annotated[str, StringConstraints(max_length=2048)]
_SIGNAL = Annotated[str, StringConstraints(max_length=128)]


class PowStamp(BaseModel):
    """A hashcash stamp over this registration (services/pow has the spec)."""
    ts: int = Field(ge=0, le=2**63 - 1)
    nonce: Annotated[str, StringConstraints(max_length=64)]


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
    # A referral: a live handle (MsgRegister 15); "" for none.
    affiliate_handle: Annotated[str, StringConstraints(max_length=64)] = ""
    # Removed from MsgRegister (11, 12; chain audit round 5): accepted by the
    # schema only so _affiliate can refuse them with a 400 that names them,
    # not drop them silently. Not in the published schema.
    affiliate_pc: SkipJsonSchema[Any] = None
    affiliate_ciphertext: SkipJsonSchema[Any] = None
    # Where the gas goes: the pc of a note the app will spend MsgRegister's
    # fee from, and that note's amount-blind v2 ciphertext (MsgShield's,
    # required).
    pc_gas: _SHORT
    ciphertext_gas: _SHORT
    # Required for the reserved lane and while shedding (428 says so); see
    # GET /gas/pow.
    pow: PowStamp | None = None


_HEX_RUN = re.compile(r"(0x)?[0-9a-fA-F]{16,}")


def _coarse(reason) -> str:
    """A refusal reason for the log: hex runs (nullifiers, keys, hashes) cut out, length bounded."""
    return _HEX_RUN.sub("<hex>", str(reason))[:120]


def _reply(status_code: int, status: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"status": status, "message": message, **extra})


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
    # The chain refuses a date that does not round-trip (Feb 31): the circuit
    # compares YYMMDD numerically, so 250231 would otherwise be dated Mar 3.
    if dd > calendar.monthrange(2000 + yy, mm)[1]:
        raise ValueError("current_date is not a calendar date")
    return calendar.timegm((2000 + yy, mm, dd, 0, 0, 0))


def _passport_key(nullifier_hex: str) -> str:
    """The prefix every grant id of one passport starts with."""
    return f"{PASSPORT_PREFIX}{nullifier_hex}:"


class _Refuse(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def _affiliate(body: RegisterGrant) -> int:
    """MsgRegister.AffiliateField: 0 for no referral, else
    H("earth.affiliate", Bytes(affiliate_handle)). Raises _Refuse for a
    malformed handle or for the removed affiliate_pc / affiliate_ciphertext."""
    removed = [n for n in ("affiliate_pc", "affiliate_ciphertext") if getattr(body, n) is not None]
    if removed:
        raise _Refuse(400, f"{' and '.join(removed)} {'is' if len(removed) == 1 else 'are'} no longer part of "
                           "MsgRegister: send affiliate_handle only; the chain mints the referral note itself")
    handle = body.affiliate_handle
    if not handle:
        return 0
    if not handles.valid_handle(handle):
        raise _Refuse(400, "affiliate_handle is not a handle (a-z, 0-9 and -, 3..32 characters, no leading or trailing dash)")
    return privacy.affiliate_field(handle)


def _precheck(body: RegisterGrant) -> tuple[str, str, bytes, bytes, bytes | None, bytes]:
    """Everything about a registration that needs no gas-check, cheapest first.

    Returns (passport nullifier hex, grant id, pc_gas, ciphertext_gas,
    DSC commitment or None, dsc_der) or raises _Refuse.
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
    affiliate_field = _affiliate(body)

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
    # note ciphertexts (and referral). Someone replaying another registration's proof with
    # notes of their own fails here, as on chain.
    if signals[config.PASSPORT_ADDRESS_INDEX] != privacy.registration_binding(idc, pc_anml, ciphertexts[0], pc_erth, ciphertexts[1], affiliate_field):
        raise _Refuse(400, "proof is bound to a different identity and notes than this registration names")

    try:
        proof_unix = _yymmdd_unix(signals[config.PASSPORT_CURRENT_DATE_INDEX])
    except ValueError as exc:
        raise _Refuse(400, str(exc))
    if abs(time.time() - proof_unix) > config.PASSPORT_DATE_MAX_SKEW_SECONDS + _DATE_SLACK_SECONDS:
        raise _Refuse(400, "current_date is too far from today; prove again")

    # The document signer's own validity, as the chain checks it first of
    # everything about the certificate (x/pki VerifyDscIssuer,
    # ErrCertExpired). An expired one is the registrant's circumstance, not
    # junk, and must not count against their network (audit-6 M1); refused
    # here it costs no gas-check either. Edges within _DATE_SLACK_SECONDS
    # are the chain's call. A certificate `cryptography` cannot read
    # (brainpool) is the chain's call too.
    if _dsc_expired(dsc_der):
        raise _Refuse(400, "the passport's document signer certificate is expired or not yet valid; "
                           "this passport cannot register")

    nullifier = privacy.field_bytes(signals[config.PASSPORT_NULLIFIER_INDEX]).hex()
    day = time.strftime("%Y-%m-%d", time.gmtime())
    # Not refused when absent: whether a DSC is required is the chain's call.
    dsc = privacy.field_bytes(signals[config.PASSPORT_DSC_KEY_INDEX]) if config.PASSPORT_DSC_KEY_INDEX < n else None
    return nullifier, f"{_passport_key(nullifier)}{day}", pc_gas, ciphertext_gas, dsc, dsc_der


def _dsc_expired(dsc_der: bytes, now: float | None = None) -> bool:
    """Whether a DSC certificate is outside its validity, by more than
    _DATE_SLACK_SECONDS of now. False when it cannot be read."""
    from cryptography import x509

    try:
        cert = x509.load_der_x509_certificate(dsc_der)
        before, after = cert.not_valid_before_utc.timestamp(), cert.not_valid_after_utc.timestamp()
    except Exception:
        return False
    now = time.time() if now is None else now
    return now < before - _DATE_SLACK_SECONDS or now > after + _DATE_SLACK_SECONDS


def _dsc_country(dsc_der: bytes) -> str | None:
    """The issuer's country (C=) of a DSC certificate, upper case, or None.

    What the chain keys its country cap by is the trust store's country for
    the CSCA that verified the DSC; the DSC's issuer name is that CSCA's
    subject, so the two agree for any DSC that chains — and only a DSC that
    chains reaches the proof verification that spends a budget. A bucket
    for the refusal budget, never a fact anything is granted on.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        attrs = x509.load_der_x509_certificate(dsc_der).issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    except Exception:
        return None
    if not attrs:
        return None
    value = str(attrs[0].value).strip().upper()
    return value[:3] if value.isascii() and value.isalpha() else None


# The chain's refusals by kind (gas-check's error is "<detail>: <base>", the
# base an x/personhood or x/pki error description). Only the kind is logged:
# the detail can name the affiliate handle, the country, a nullifier.
# Codes beside each are the chain's (x/personhood unless named); gas-check
# reports the error text only. Of the codes added with handles, 1122
# (ErrHandleTaken), 1125 (ErrHandleMovedOut), 1126 (ErrCaretakerMovedOut) and
# x/dex 1120 (ErrPoolCap) belong to msgs no registration check reaches.
_PROOF_REFUSAL = "invalid registration proof"
_REFUSAL_KINDS = (
    (_PROOF_REFUSAL, "invalid proof"),
    ("daily registration limit reached for this document signer or country", "rate cap"),
    ("proof public inputs do not match", "public inputs"),
    ("this registration has already been used", "binding used"),  # 1124 ErrBindingUsed
    ("passport is already registered to this identity commitment", "replay"),  # 1123 ErrRegistrationReplay
    ("affiliate_handle is not a live handle", "affiliate"),  # 1121 ErrNoReferrer
    ("identity tree full", "tree full"),  # 1120 ErrIdentityTreeFull
    ("has been revoked", "revoked"),
    ("no registration verifying key configured", "no verifying key"),
    ("invalid certificate", "certificate"),
    ("no trusted issuing CSCA found", "certificate"),
    ("certificate signature verification failed", "certificate"),
    ("certificate not valid at current time", "certificate"),
    ("certificate is not a Document Signer", "certificate"),
    ("too many candidate issuing CSCAs", "certificate"),
)


# Refusals the registrant's own circumstances decide, which do not count
# against their client (audit-6 M1): a signer or country at its daily cap.
# The chain checks the cap only after the certificate has chained, so it is
# not junk anyone mints with a made-up certificate. (An expired document
# signer is the other such refusal; _precheck answers it 400 before the
# queue, since the chain refuses it before anything else and a made-up
# certificate would otherwise be a free refusal.)
_USER_STATE_KINDS = frozenset({"rate cap"})


def _refusal_kind(error) -> str:
    text = str(error or "").strip()
    for base, kind in _REFUSAL_KINDS:
        if text == base or text.endswith(": " + base) or (base == "has been revoked" and base in text):
            return kind
    return "other"


def _pow_needed(bits: int, message: str) -> JSONResponse:
    return _reply(428, "error", message, pow={"version": pow.VERSION, "bits": bits})


@router.get("/pow", summary="The proof of work /gas/register needs right now")
def pow_params(request: Request):
    # The network's state, or this client's when it is over its refusal
    # budget (audit-6 M1): either way its requests need the shedding bits.
    shed = ratelimit.shedding() is not None or \
        ratelimit.client_refused_out(ratelimit.refusal_key(ratelimit.client_ip(request)))
    return {
        "version": pow.VERSION,
        "algorithm": "sha256",
        "input": pow.VERSION + ":<ts>:<public_signals[%d]>:<public_signals[%d]>:<nonce>"
                 % (config.PASSPORT_ADDRESS_INDEX, config.PASSPORT_NULLIFIER_INDEX),
        # What admits a request on every path right now: the reserved lane's,
        # or shedding's while the network budget (or this client's refusal
        # budget) is spent. A signer's or
        # country's own budget can ask more of its requests; a 428 says so.
        "bits": pow.required_bits(shedding=shed),
        "reserved_bits": pow.required_bits(shedding=False),
        "shedding_bits": pow.required_bits(shedding=True),
        "shedding": shed,
        "max_age_seconds": config.POW_MAX_AGE_SECONDS,
    }


def _inline_schema(model) -> dict:
    """model's JSON schema with its $defs inlined (OpenAPI resolves no local $defs)."""
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def walk(o):
        if isinstance(o, dict):
            ref = o.get("$ref", "")
            if ref.startswith("#/$defs/"):
                return walk(defs[ref[len("#/$defs/"):]])
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(schema)


@router.post("/register", summary="Fund a fee note for a registration the chain would accept",
             openapi_extra={"requestBody": {"required": True, "content": {
                 "application/json": {"schema": _inline_schema(RegisterGrant)}}}})
async def register(request: Request):
    # The body is validated here, after the request is counted (audit-5
    # L13): as a FastAPI parameter it was validated first, and a body that
    # failed the schema (422) never reached the per-client window.
    ip = ratelimit.client_ip(request)
    client = ratelimit.client_key(ip)
    # Refusals count per subscriber (an IPv6 /64), the request window per
    # /48 (audit-6 M1).
    refuser = ratelimit.refusal_key(ip)
    if not ratelimit.allow(client):
        return _reply(429, "error", "too many requests; try again later")
    try:
        body = RegisterGrant.model_validate_json(await request.body())
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={
            "status": "error", "message": "the body is not a registration request",
            "detail": jsonable_encoder(exc.errors(include_url=False, include_input=False))})
    try:
        nullifier, grant_id, pc_gas, ciphertext_gas, dsc, dsc_der = _precheck(body)
    except _Refuse as exc:
        return _reply(exc.status_code, "error", str(exc))
    # Replay and cap before the check: both are a table read, the check is a
    # proof verification. claim() decides again after it, atomically.
    if replay.peek(grant_id, key_prefix=_passport_key(nullifier), once_per=GRANT_ONCE_PER_SECONDS):
        return _reply(409, "error", "already granted")
    # Whether this is a switch is gas-check's answer, so only when both caps
    # are spent is the request refused before it; otherwise claim() decides
    # by kind after the check.
    if replay.limit_reached(PASSPORT_PREFIX, config.REGISTER_GRANT_MAX_PER_DAY) and \
            replay.limit_reached(PASSPORT_PREFIX, config.REGISTER_SWITCH_GRANT_MAX_PER_DAY, kind=SWITCH):
        return _reply(429, "error", "free gas limit reached; try again tomorrow")

    # Shedding: the network's, this signer's or this country's budget of
    # verification failures is spent, or this client's of refusals. Such a
    # request is queued only with a proof of work at the shedding
    # difficulty. A client over its refusal budget used to be refused 429
    # outright (audit-6 M1): on a CGNAT address or a carrier's shared prefix
    # three junk requests an hour locked everyone there out, with no way to
    # pay through.
    country = _dsc_country(dsc_der)
    shed = ratelimit.shedding(dsc, country) or ("client" if ratelimit.client_refused_out(refuser) else None)
    # The reserved lane: a passport not yet granted (peek, above) from a
    # Document Signer the chain already holds registrations from, with a
    # proof of work, whose
    # dsc_der really is the signer public_signals names (checked last: it
    # hashes the key, and only a request that paid the work gets that far;
    # a key past dsccommit.LANE_MAX_KEY_BYTES is never hashed and takes the
    # ordinary lane).
    candidate = dsc is not None and knowndsc.is_known(dsc)
    need = pow.required_bits(shedding=shed is not None)
    bits, digest = 0, None
    if body.pow is not None and (shed or candidate):
        binding = body.public_signals[config.PASSPORT_ADDRESS_INDEX]
        nf_signal = body.public_signals[config.PASSPORT_NULLIFIER_INDEX]
        try:
            bits, digest = pow.check(body.pow.ts, body.pow.nonce, binding, nf_signal)
        except pow.Rejected as exc:
            if shed:
                return _pow_needed(need, str(exc))
            bits = 0  # not needed: the ordinary lane
    if shed and bits < need:
        if shed == "client":
            return _pow_needed(need, f"too many refused registrations from this network lately; "
                                     f"attach a proof of work of {need} bits (GET /gas/pow)")
        return _pow_needed(need, f"too many failed registrations for this {shed} right now; "
                                 f"attach a proof of work of {need} bits (GET /gas/pow)")
    if bits >= need and digest is not None:
        # Consumed at once, before the await below (audit-6 L1): checked
        # and consumed across lane_commitment, concurrent copies of one
        # request each passed check(), and one stamp admitted several
        # shed or priority checks. Given back below if it is not relied on.
        pow.consume(digest)
    else:
        digest = None  # not relied on: still the wallet's to use
    priority = False
    if candidate and digest is not None:
        # Off the event loop, one at a time, a key of at most RSA 4096
        # (audit-5 M1). A certificate that is not the signer it names is
        # refused here: the chain refuses it for certain ("proof is not
        # bound to the supplied DSC"), so it is never queued.
        lane = await dsccommit.lane_commitment(dsc_der)
        if lane is not None and lane != dsc:
            pow.forget(digest)
            return _reply(400, "error", "dsc_der is not the Document Signer public_signals names")
        # At most one priority check per signer waits or runs (audit-5
        # M3); a second one naming it takes the ordinary lane. Taken here
        # and given back in the finally below, with no await between.
        priority = lane == dsc and ratelimit.take_signer_lane(dsc)
    if digest is not None and not (shed or priority):
        pow.forget(digest)  # this request's own consume: the ordinary lane does not rely on it
        digest = None

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
    }
    if body.affiliate_handle:
        msg["affiliate_handle"] = body.affiliate_handle
    try:
        with ratelimit.one_at_a_time(client):
            verdict = await gascheck.registration(msg, priority=priority)
    except ratelimit.Busy:
        pow.forget(digest)
        return _reply(429, "error", "a check for this client is already running; wait for it")
    except gascheck.Unavailable as exc:
        pow.forget(digest)
        logger.error("registration check unavailable: %s", _coarse(exc))
        return _reply(503, "error", "verification is unavailable; try again shortly")
    finally:
        if priority:
            ratelimit.release_signer_lane(dsc)
    if not verdict.get("ok"):
        kind = _refusal_kind(verdict.get("error"))
        if kind == "invalid proof":
            # A refusal that cost a proof verification spends every budget
            # it falls under. Any other (a country or signer at its daily
            # cap, a DSC that does not chain) was decided before the
            # verifier ran, and a real registrant meeting a cap must not
            # shed anyone else.
            ratelimit.note_refusal(dsc, country)
        # Every refusal, cheap ones included and in either lane, counts
        # against the client (its /64) that sent it (audit-5 M3): a client
        # that only produces refusals pays a proof of work for each request
        # for a while. Not a daily cap: that is the registrant's
        # circumstance, not junk (audit-6 M1). No refusal demotes the signer
        # it named: that was anyone's to trigger with the signer's public
        # certificate, and it evicted the signer's real registrants from the
        # lane.
        if kind not in _USER_STATE_KINDS:
            ratelimit.note_client_refusal(refuser)
        # The chain's own reason — "passport expired", "daily cap reached" —
        # is what the user needs, and it says nothing they did not send. The
        # log keeps only its kind: no nullifier, handle or country.
        logger.info("registration check refused: %s", kind)
        return _reply(403, "error", f"the chain would not accept this registration: {verdict.get('error')}")
    if verdict.get("nullifier") != nullifier:
        # gas-check read the nullifier from the chain's nullifier_index; ours
        # disagrees, so PASSPORT_NULLIFIER_INDEX does not match the chain.
        logger.error("gas-check nullifier differs from public_signals[%d]; check PASSPORT_NULLIFIER_INDEX",
                     config.PASSPORT_NULLIFIER_INDEX)
        return _reply(503, "error", "verification is unavailable; try again shortly")
    switched = verdict.get("switched") is True
    return await _grant_note(grant_id, _passport_key(nullifier), pc_gas, ciphertext_gas, switched)


async def _grant_note(grant_id: str, key_prefix: str, pc: bytes, ciphertext: bytes,
                      switched: bool = False) -> JSONResponse:
    """Claims grant_id, then shields the dust to pc. Claimed under its id alone, no address.

    Claim before sending: the insert is atomic, so two concurrent requests with
    the same id cannot both reach the chain.
    """
    try:
        claimed = replay.claim(grant_id, prefix=PASSPORT_PREFIX,
                               max_per_day=config.REGISTER_SWITCH_GRANT_MAX_PER_DAY if switched
                               else config.REGISTER_GRANT_MAX_PER_DAY,
                               key_prefix=key_prefix, once_per=GRANT_ONCE_PER_SECONDS,
                               kind=SWITCH if switched else "")
    except replay.LimitReached as exc:
        logger.warning("%s %s payout limit reached; refusing a registration grant", exc,
                       "switch" if switched else "registration")
        return _reply(429, "error", "free gas limit reached; try again tomorrow")
    if not claimed:
        return _reply(409, "error", "already granted")

    try:
        tx_hash = await chain.shield_dust(pc, ciphertext)
    except chain.SendUnresolved as exc:
        # Always names its tx (chain._resolve raises it with the signed
        # tx's hash). Broadcast, and the chain did not show it within the wait. The id
        # stays claimed: a tx still in a mempool will land, and releasing
        # would let it be paid twice. The app holds the hash and can watch for
        # it; this side keeps no record that ties it to the passport.
        logger.error("gas note shield is unresolved: %s", exc)
        return _reply(202, "pending", "gas is on its way", tx_hash=exc.tx_hash)
    except Exception as exc:
        # chain.shield_dust raises an ordinary exception only when the tx
        # demonstrably moved nothing: it failed before the post, the
        # connection was never made, CheckTx refused it, or the hash lookup
        # found it included and failed. Any other failure after the post
        # (a non-200 from a proxy included) was resolved by hash or is
        # SendUnresolved above.
        replay.release(grant_id)
        # Not logger.exception: a cosmpy error names the tx hash.
        logger.error("gas note shield failed: %s: %s", exc.__class__.__name__, _coarse(exc))
        return _reply(502, "error", "the grant could not be sent; try again")

    # Logged without the tx hash, the pc or the passport. The registration
    # and the shield are both public; a log line naming the shield's tx at the
    # moment a passport checked out would tie the two together by timing.
    logger.info("registration gas note sent")
    return _reply(200, "success", "gas note sent", tx_hash=tx_hash)
