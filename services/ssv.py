"""AdMob Server-Side Verification.

Google signs the rewarded-ad callback so the backend can trust that the ad was
really watched. This is the whole Sybil defence for ads-for-gas: without a valid
signature anyone could mint dust by calling the endpoint in a loop.

The details here are fiddly and were arrived at the hard way, so they are spelled
out rather than left to be rediscovered:

  * The signed content is everything in the query string *before* `&signature=`,
    URL-**decoded**. Signing the raw encoded string does not verify.
  * The signature parameter is URL-safe base64 and arrives without padding.
  * It is ECDSA over SHA-256, DER-encoded.
  * Keys rotate, so they are fetched from Google and cached.
"""
import base64
import hashlib
import logging
import time
from urllib.parse import unquote

import httpx
from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.util import sigdecode_der

import config

logger = logging.getLogger(__name__)

_keys: dict[str, str] = {}
_fetched_at: float = 0.0

# The soonest an unknown key id may trigger another fetch. Without it, junk key
# ids in unsigned callbacks would be a free way to make this service hammer
# gstatic — the signature has not been checked when the refresh happens, and it
# cannot be: checking it is what needs the key.
_MISS_REFETCH_INTERVAL = 300.0
_last_miss_fetch: float = 0.0


async def public_keys(force: bool = False) -> dict[str, str]:
    """Google's SSV verifier keys, keyed by id. Cached for GOOGLE_SSV_KEYS_TTL."""
    global _keys, _fetched_at

    if not force and _keys and time.time() - _fetched_at < config.GOOGLE_SSV_KEYS_TTL:
        return _keys

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(config.GOOGLE_SSV_KEYS_URL)
            response.raise_for_status()
            fetched = {
                str(k["keyId"]): k["pem"]
                for k in response.json().get("keys", [])
                if k.get("keyId") is not None and k.get("pem")
            }
        if fetched:
            _keys, _fetched_at = fetched, time.time()
            logger.info("fetched %d AdMob SSV keys", len(fetched))
    except Exception as exc:
        # Keep serving on the cached set if there is one. Failing closed on a
        # transient Google outage would stop onboarding entirely.
        logger.warning("could not refresh AdMob SSV keys: %s", exc)

    return _keys


async def keys_for(key_id: str) -> dict[str, str]:
    """The key set, refreshed if it does not contain key_id.

    Google rotates these, and the TTL alone makes a rotation look like a day of
    forged callbacks: every real ad view is checked against a stale set and
    refused, users watch ads and get no dust, and it fixes itself 24 hours
    later. A miss is the signal that the cache is behind, so it is worth one
    fetch rather than waiting out the TTL.
    """
    global _last_miss_fetch

    keys = await public_keys()
    if not key_id or key_id in keys:
        return keys

    # Rate-limited on the attempt, not on the success. Keying this off the
    # last *successful* fetch would leave a Google outage — which is when a
    # refresh fails and the timestamp does not move — refetching on every
    # single callback for as long as the outage lasted.
    now = time.time()
    if now - _last_miss_fetch < _MISS_REFETCH_INTERVAL:
        return keys
    _last_miss_fetch = now

    logger.info("key id %s not in the cached set; refreshing", key_id)
    return await public_keys(force=True)


def signed_content(query_string: str) -> str:
    """The exact text the signature covers: the prefix before `&signature=`, decoded.

    Anything decided on must be read from this, not from the raw query string.
    Decoding is many-to-one — `&` and `%26` decode alike — so the raw string can
    be re-encoded without disturbing the signature, and a parser run over it
    sees whatever parameters the re-encoding makes up.
    """
    return unquote(query_string.split("&signature=")[0])


def signed_params(query_string: str) -> list[tuple[str, str]]:
    """The signed parameters, split out of signed_content in order.

    Split on every `&` of the decoded text, because that is the only reading of
    it that does not depend on how the raw string was encoded. A value that
    itself contained an `&` comes out as an extra parameter; that is the point.
    """
    return [
        (name, value)
        for name, _, value in (item.partition("=") for item in signed_content(query_string).split("&"))
    ]


def verify(query_string: str, signature_b64: str, key_id: str, keys: dict[str, str]) -> bool:
    """Checks the SSV signature over a raw query string."""
    pem = keys.get(key_id)
    if not pem:
        logger.warning("unknown AdMob SSV key id %s", key_id)
        return False

    content = signed_content(query_string).encode("utf-8")

    padded = unquote(signature_b64)
    padded += "=" * (-len(padded) % 4)
    try:
        signature = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        logger.warning("malformed AdMob SSV signature: %s", exc)
        return False

    try:
        return VerifyingKey.from_pem(pem).verify(
            signature, content, hashfunc=hashlib.sha256, sigdecode=sigdecode_der
        )
    except BadSignatureError:
        logger.warning("AdMob SSV signature did not verify")
        return False
    except Exception as exc:
        logger.warning("AdMob SSV verification error: %s", exc)
        return False
