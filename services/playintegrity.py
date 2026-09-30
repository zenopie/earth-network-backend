"""Verifying a Google Play Integrity token.

The token is encrypted and signed by Google, and the simplest correct way to
open it is to ask Google: decodeIntegrityToken, authenticated as a service
account in the Cloud project linked to the app in Play Console. What comes back
is Google's verdict, and every field that matters is checked here — a decoded
token only says what Google saw, not that it is good.

What a passing token proves: a copy of `network.erth.wallet` that Google Play
recognises, on a device that passes Play's device integrity check, asked for it
over exactly this nonce, recently.
"""
import asyncio
import base64
import json
import logging
import time

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

import config

logger = logging.getLogger(__name__)

_SCOPE = "https://www.googleapis.com/auth/playintegrity"
_credentials: service_account.Credentials | None = None


class IntegrityError(Exception):
    """The token does not prove what it claims. The message says which check failed."""


class Unavailable(Exception):
    """Google could not be asked, or this service is not configured to ask it."""


def configured() -> bool:
    return bool(config.GOOGLE_SERVICE_ACCOUNT_JSON)


def _load_credentials() -> service_account.Credentials:
    """The service account, from raw JSON or base64 of it — base64 survives an SDL."""
    raw = config.GOOGLE_SERVICE_ACCOUNT_JSON.strip()
    if not raw.startswith("{"):
        raw = base64.b64decode(raw).decode("utf-8")
    return service_account.Credentials.from_service_account_info(json.loads(raw), scopes=[_SCOPE])


def _access_token() -> str:
    global _credentials
    if _credentials is None:
        _credentials = _load_credentials()
    if not _credentials.valid:
        _credentials.refresh(GoogleAuthRequest())
    return _credentials.token


async def decode(token: str) -> dict:
    """Google's verdict on `token`, as tokenPayloadExternal."""
    if not configured():
        raise Unavailable("GOOGLE_SERVICE_ACCOUNT_JSON is unset")
    try:
        # google-auth refreshes over requests, which blocks.
        access = await asyncio.to_thread(_access_token)
        async with httpx.AsyncClient(timeout=config.CHAIN_HTTP_TIMEOUT) as client:
            resp = await client.post(
                f"https://playintegrity.googleapis.com/v1/{config.ANDROID_PACKAGE}:decodeIntegrityToken",
                headers={"Authorization": f"Bearer {access}"},
                json={"integrity_token": token},
            )
    except Exception as exc:
        raise Unavailable(f"could not reach Play Integrity: {exc}") from exc
    if resp.status_code == 400:
        # Google's answer to a token that is malformed, expired, or not ours.
        raise IntegrityError("Google refused the token")
    if resp.status_code != 200:
        raise Unavailable(f"Play Integrity answered {resp.status_code}")
    payload = resp.json().get("tokenPayloadExternal")
    if not isinstance(payload, dict):
        raise Unavailable("Play Integrity answered without a payload")
    return payload


def _unpadded(text: str) -> str:
    return text.rstrip("=")


def check(payload: dict, expected_nonce: str, now: float | None = None) -> None:
    """Raises IntegrityError unless `payload` is a good verdict over `expected_nonce`."""
    now = time.time() if now is None else now
    request = payload.get("requestDetails") or {}
    app = payload.get("appIntegrity") or {}
    device = payload.get("deviceIntegrity") or {}

    if request.get("requestPackageName") != config.ANDROID_PACKAGE:
        raise IntegrityError("token was requested by a different package")
    # Google echoes the nonce as sent; padding is the one thing clients vary on.
    if _unpadded(request.get("nonce") or "") != _unpadded(expected_nonce):
        raise IntegrityError("nonce does not match this challenge and address")
    try:
        age = now - int(request.get("timestampMillis")) / 1000
    except (TypeError, ValueError) as exc:
        raise IntegrityError("token has no request timestamp") from exc
    if age > config.CHALLENGE_TTL_SECONDS or age < -60:
        raise IntegrityError("token is outside the time window")

    verdict = app.get("appRecognitionVerdict")
    accepted = {"PLAY_RECOGNIZED"} | ({"UNRECOGNIZED_VERSION"} if config.PLAY_INTEGRITY_ALLOW_UNRECOGNIZED else set())
    if verdict not in accepted:
        raise IntegrityError(f"app is not recognised by Play ({verdict})")
    # Absent when the verdict is UNEVALUATED; required otherwise.
    if app.get("packageName") != config.ANDROID_PACKAGE:
        raise IntegrityError("verdict is for a different package")
    if "MEETS_DEVICE_INTEGRITY" not in (device.get("deviceRecognitionVerdict") or []):
        raise IntegrityError("device does not pass Play's integrity check")
