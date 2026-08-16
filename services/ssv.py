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


async def public_keys() -> dict[str, str]:
    """Google's SSV verifier keys, keyed by id. Cached for GOOGLE_SSV_KEYS_TTL."""
    global _keys, _fetched_at

    if _keys and time.time() - _fetched_at < config.GOOGLE_SSV_KEYS_TTL:
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


def verify(query_string: str, signature_b64: str, key_id: str, keys: dict[str, str]) -> bool:
    """Checks the SSV signature over a raw query string."""
    pem = keys.get(key_id)
    if not pem:
        logger.warning("unknown AdMob SSV key id %s", key_id)
        return False

    content = unquote(query_string.split("&signature=")[0]).encode("utf-8")

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
