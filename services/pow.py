"""Hashcash on /gas/register: what a request pays for the reserved lane, and
to be queued at all while a refusal budget is spent.

A stamp is computed by the wallet, per request, and costs this side one
SHA-256 to check:

    input  = "earth-gas-pow/v1:<ts>:<binding>:<nullifier>:<nonce>"   (ASCII)
    digest = SHA-256(input)
    valid when digest has at least `bits` leading zero bits

- ts: unix seconds when the wallet made the stamp; accepted within
  POW_MAX_AGE_SECONDS of this server's clock, either way.
- binding, nullifier: public_signals[PASSPORT_ADDRESS_INDEX] and
  public_signals[PASSPORT_NULLIFIER_INDEX] exactly as the request sends them
  (decimal strings). The binding covers idc, both pcs and both note
  ciphertexts, so a stamp is good for one registration and nothing else.
- nonce: 1..64 characters of [0-9A-Za-z], the wallet's counter.

The request carries it as `"pow": {"ts": <int>, "nonce": "<str>"}`. Each
stamp is accepted once (a replay of a stamp that was relied on is 428); one
that was relied on for a check that then could not run (503, or the client's
check already in flight) is given back.

Difficulty (`bits`) is adaptive: POW_RESERVED_BITS for the reserved lane,
POW_SHED_BITS while a refusal budget the request falls under is spent, plus
up to POW_LOAD_EXTRA_BITS as the gas-check queue fills, capped at
POW_MAX_BITS. GET /gas/pow says what admits a request right now; a 428
answer carries the bits that request needs.
"""
import hashlib
import re
import time
from collections import OrderedDict

import config
from services import gascheck

VERSION = "earth-gas-pow/v1"
NONCE = re.compile(r"[0-9A-Za-z]{1,64}")

# digest -> expiry (monotonic seconds), oldest first.
_seen: "OrderedDict[bytes, float]" = OrderedDict()


class Rejected(Exception):
    """The stamp cannot be used (stale, reused, malformed); the message says why."""


def stamp_input(ts: int, binding: str, nullifier: str, nonce: str) -> bytes:
    return f"{VERSION}:{ts}:{binding}:{nullifier}:{nonce}".encode("ascii")


def leading_zero_bits(digest: bytes) -> int:
    n = int.from_bytes(digest, "big")
    return len(digest) * 8 - n.bit_length()


def required_bits(*, shedding: bool) -> int:
    """The difficulty a stamp needs now: the reserved lane's, or shedding's."""
    base = config.POW_SHED_BITS if shedding else config.POW_RESERVED_BITS
    return min(base + int(gascheck.load() * config.POW_LOAD_EXTRA_BITS), config.POW_MAX_BITS)


def check(ts: int, nonce: str, binding: str, nullifier: str, now: float | None = None) -> tuple[int, bytes]:
    """(leading zero bits, digest) of a stamp. Raises Rejected."""
    if not NONCE.fullmatch(nonce):
        raise Rejected("pow.nonce must be 1-64 characters of [0-9A-Za-z]")
    now = time.time() if now is None else now
    if abs(now - ts) > config.POW_MAX_AGE_SECONDS:
        raise Rejected("pow.ts is too far from now; make a new stamp")
    digest = hashlib.sha256(stamp_input(ts, binding, nullifier, nonce)).digest()
    _expire()
    if digest in _seen:
        raise Rejected("this proof of work was already used; make a new stamp")
    return leading_zero_bits(digest), digest


def consume(digest: bytes) -> None:
    """Marks a stamp used (it was relied on: lane or shedding)."""
    _seen[digest] = time.monotonic() + 2 * config.POW_MAX_AGE_SECONDS
    while len(_seen) > config.POW_MAX_TRACKED:
        _seen.popitem(last=False)


def forget(digest: bytes | None) -> None:
    """Gives a stamp back when the check it paid for never ran."""
    if digest is not None:
        _seen.pop(digest, None)


def _expire() -> None:
    now = time.monotonic()
    while _seen:
        d, exp = next(iter(_seen.items()))
        if exp > now:
            break
        _seen.popitem(last=False)


def solve(ts: int, binding: str, nullifier: str, bits: int) -> str:
    """A nonce for a stamp, the way a wallet finds one. For tests and tooling."""
    i = 0
    while True:
        nonce = format(i, "x")
        if leading_zero_bits(hashlib.sha256(stamp_input(ts, binding, nullifier, nonce)).digest()) >= bits:
            return nonce
        i += 1


def reset() -> None:
    _seen.clear()
