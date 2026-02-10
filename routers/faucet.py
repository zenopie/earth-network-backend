# /routers/faucet.py - Ads for Gas implementation

import base64
import hashlib
import json
import os
import time
from urllib.parse import unquote

from ecdsa import VerifyingKey, BadSignatureError
from ecdsa.util import sigdecode_der
import httpx

from fastapi import APIRouter, Request
from secret_sdk.core.feegrant import MsgGrantAllowance, BasicAllowance
from secret_sdk.core.coins import Coins, Coin
from datetime import datetime

import config
from services.tx_queue import get_tx_queue

router = APIRouter()

# Cache for used transaction IDs to prevent replay attacks
USED_TRANSACTION_IDS = set()
USED_TX_FILE = "used_tx_ids.json"

# Google's public keys for SSV verification (cached)
GOOGLE_KEYS_CACHE = {}
GOOGLE_KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"
GOOGLE_KEYS_CACHE_DURATION = 86400  # 24 hours


def load_used_tx_ids():
    """Load used transaction IDs from file."""
    global USED_TRANSACTION_IDS
    try:
        if os.path.exists(USED_TX_FILE):
            with open(USED_TX_FILE, 'r') as f:
                USED_TRANSACTION_IDS = set(json.load(f))
    except Exception as e:
        print(f"[AdsForGas] Could not load used tx IDs: {e}", flush=True)
        USED_TRANSACTION_IDS = set()


def save_used_tx_ids():
    """Save used transaction IDs to file."""
    try:
        with open(USED_TX_FILE, 'w') as f:
            json.dump(list(USED_TRANSACTION_IDS), f)
    except Exception as e:
        print(f"[AdsForGas] Could not save used tx IDs: {e}", flush=True)


async def fetch_google_keys() -> dict:
    """Fetch Google's public keys for SSV verification."""
    global GOOGLE_KEYS_CACHE

    now = time.time()
    if GOOGLE_KEYS_CACHE.get("keys") and now - GOOGLE_KEYS_CACHE.get("fetched_at", 0) < GOOGLE_KEYS_CACHE_DURATION:
        return GOOGLE_KEYS_CACHE["keys"]

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(GOOGLE_KEYS_URL)
            response.raise_for_status()
            data = response.json()

            # Parse keys into usable format
            keys = {}
            for key_data in data.get("keys", []):
                key_id = key_data.get("keyId")
                pem = key_data.get("pem")
                if key_id and pem:
                    keys[str(key_id)] = pem

            GOOGLE_KEYS_CACHE = {"keys": keys, "fetched_at": now}
            print(f"[AdsForGas] Fetched {len(keys)} Google verification keys", flush=True)
            return keys
    except Exception as e:
        print(f"[AdsForGas] Failed to fetch Google keys: {e}", flush=True)
        # Return cached keys if available
        return GOOGLE_KEYS_CACHE.get("keys", {})


def verify_ssv_signature(query_string: str, signature_b64: str, key_id: str, keys: dict) -> bool:
    """Verify the SSV callback signature using Google's public key."""
    try:
        pem_key = keys.get(key_id)
        if not pem_key:
            print(f"[AdsForGas] Key ID {key_id} not found in Google keys", flush=True)
            return False

        # Content is everything BEFORE &signature= in the exact order it appears
        # IMPORTANT: Google signs the URL-DECODED content, not the raw encoded string
        content_str = query_string.split("&signature=")[0]
        content_str = unquote(content_str)  # URL decode the content
        content = content_str.encode('utf-8')

        print(f"[AdsForGas] FULL content to verify: {content_str}", flush=True)
        print(f"[AdsForGas] Content bytes length: {len(content)}", flush=True)

        # Decode the signature (URL-safe base64)
        sig_decoded = unquote(signature_b64)
        print(f"[AdsForGas] Raw signature param: {signature_b64}", flush=True)
        # Add padding if needed
        padding = 4 - len(sig_decoded) % 4
        if padding != 4:
            sig_decoded += "=" * padding
        print(f"[AdsForGas] Signature with padding: {sig_decoded}", flush=True)
        signature = base64.urlsafe_b64decode(sig_decoded)

        print(f"[AdsForGas] Decoded signature length: {len(signature)} bytes", flush=True)

        # Verify using ecdsa library
        print(f"[AdsForGas] Using key ID: {key_id}, PEM starts with: {pem_key[:50]}...", flush=True)
        verifying_key = VerifyingKey.from_pem(pem_key)
        return verifying_key.verify(
            signature,
            content,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_der,
        )

    except BadSignatureError:
        print(f"[AdsForGas] Invalid SSV signature (cryptographic verification failed)", flush=True)
        return False
    except Exception as e:
        print(f"[AdsForGas] SSV verification error: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return False


@router.get("/ads-callback", summary="AdMob SSV callback endpoint")
async def admob_ssv_callback(request: Request):
    """
    Server-Side Verification callback from AdMob.
    AdMob calls this endpoint when a user completes watching a rewarded ad.
    The custom_data parameter should contain the user's wallet address.
    """
    try:
        # Log that callback was received
        print(f"[AdsForGas] SSV callback received: {request.url}", flush=True)

        # Get the RAW query string bytes - this preserves URL encoding exactly as sent
        raw_query_bytes = request.scope.get('query_string', b'')
        query_string = raw_query_bytes.decode('utf-8')
        print(f"[AdsForGas] Raw query string: {query_string[:150]}...", flush=True)

        # Parse query parameters
        params = dict(request.query_params)
        print(f"[AdsForGas] Params: {params}", flush=True)

        ad_unit = params.get("ad_unit", "")
        custom_data = params.get("custom_data", "")  # User's wallet address
        transaction_id = params.get("transaction_id", "")
        signature = params.get("signature", "")
        key_id = params.get("key_id", "")

        # Validate required parameters
        if not all([custom_data, transaction_id, signature, key_id]):
            print(f"[AdsForGas] Missing required SSV parameters", flush=True)
            return {"status": "error", "message": "Missing parameters"}

        # Check for replay attack
        load_used_tx_ids()
        if transaction_id in USED_TRANSACTION_IDS:
            print(f"[AdsForGas] Replay attack detected: {transaction_id}", flush=True)
            return {"status": "error", "message": "Transaction already processed"}

        # Verify the ad unit matches our configuration
        # Google sends just the numeric ID, not the full ca-app-pub format
        expected_ad_unit = config.ADMOB_AD_UNIT_ID.split("/")[-1] if "/" in config.ADMOB_AD_UNIT_ID else config.ADMOB_AD_UNIT_ID
        if ad_unit and ad_unit != expected_ad_unit:
            print(f"[AdsForGas] Invalid ad unit: {ad_unit} (expected {expected_ad_unit})", flush=True)
            return {"status": "error", "message": "Invalid ad unit"}

        # Fetch Google's public keys and verify signature
        keys = await fetch_google_keys()
        if not verify_ssv_signature(query_string, signature, key_id, keys):
            print(f"[AdsForGas] SSV signature verification failed", flush=True)
            return {"status": "error", "message": "Invalid signature"}

        # Mark transaction as used
        USED_TRANSACTION_IDS.add(transaction_id)
        save_used_tx_ids()

        address = custom_data.strip()
        print(f"[AdsForGas] Reward verified for {address}, tx: {transaction_id}", flush=True)

        # Grant gas allowance directly
        tx_queue = get_tx_queue()

        # Grant allowance: 0.2 SCRT (200000 uscrt) for gas with 1 hour expiration
        now_in_seconds = int(time.time())
        expiration_time_in_seconds = now_in_seconds + (1 * 3600)  # 1 hour

        expiration_datetime = datetime.fromtimestamp(expiration_time_in_seconds).isoformat() + "Z"
        allowance = BasicAllowance(
            spend_limit=Coins([Coin(denom="uscrt", amount="200000")]),
            expiration=expiration_datetime
        )

        grant_msg = MsgGrantAllowance(
            granter=tx_queue.wallet_address,
            grantee=address,
            allowance=allowance
        )

        # Submit through transaction queue (don't wait for confirmation)
        tx_result = await tx_queue.submit(
            msg_list=[grant_msg],
            gas=200000,
            memo="Ads for gas grant",
            wait_for_confirmation=False
        )

        if not tx_result.success:
            print(f"[AdsForGas] Grant transaction failed: {tx_result.error}", flush=True)
            return {"status": "error", "message": "Grant transaction failed"}

        print(f"[AdsForGas] Gas allowance granted to {address}, tx: {tx_result.tx_hash}", flush=True)
        return {"status": "success"}

    except Exception as e:
        print(f"[AdsForGas] SSV callback error: {e}", flush=True)
        return {"status": "error", "message": str(e)}


# Initialize cache on module load
load_used_tx_ids()
