"""Single-use challenges that tie a device attestation to one address.

An attestation proves "a genuine copy of the app on a real device asked for
this" — but only about whatever bytes the app fed into it. Without a challenge
the app would attest the bare address, and one captured attestation could be
replayed forever. So the server hands out 32 random bytes, the app attests
SHA-256(challenge || address), and the challenge is spent the first time
anyone presents it, whether or not the attestation then verifies.

In memory rather than SQLite: a challenge lives for minutes, and losing the set
on a restart costs a user one retry. The replay table is what has to survive.
"""
import base64
import hashlib
import secrets
import threading
import time

import config

_lock = threading.Lock()
_pending: dict[str, tuple[str, float]] = {}


class Busy(Exception):
    """Too many challenges outstanding; refuse rather than grow without bound."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def bound_digest(challenge: str, address: str) -> bytes:
    """What the app attests: SHA-256 of the raw challenge bytes then the address."""
    return hashlib.sha256(b64url_decode(challenge) + address.encode("utf-8")).digest()


def _prune(now: float) -> None:
    for key in [k for k, (_, expires) in _pending.items() if expires <= now]:
        del _pending[key]


def issue(address: str) -> str:
    """Returns a fresh challenge for `address`, valid for CHALLENGE_TTL_SECONDS."""
    now = time.time()
    with _lock:
        _prune(now)
        if len(_pending) >= config.CHALLENGE_MAX_PENDING:
            raise Busy()
        challenge = b64url_encode(secrets.token_bytes(32))
        _pending[challenge] = (address, now + config.CHALLENGE_TTL_SECONDS)
        return challenge


def consume(challenge: str, address: str) -> bytes | None:
    """Spends `challenge` and returns the digest the app should have attested.

    None if the challenge is unknown, expired, already spent, or was issued for
    a different address. It is removed in every one of those cases except the
    unknown one: a challenge presented with the wrong address has been seen by
    someone it was not issued to, and is no longer worth keeping.
    """
    with _lock:
        entry = _pending.pop(challenge, None)
    if entry is None:
        return None
    issued_to, expires = entry
    if issued_to != address or expires <= time.time():
        return None
    try:
        return bound_digest(challenge, address)
    except ValueError:
        return None


def reset() -> None:
    """Forgets every challenge. For tests."""
    with _lock:
        _pending.clear()
