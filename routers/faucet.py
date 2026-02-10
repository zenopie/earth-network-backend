# /routers/faucet.py - Ads for Gas implementation

import base64
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import httpx

from fastapi import APIRouter, HTTPException, Depends, Request
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.core.feegrant import MsgGrantAllowance, BasicAllowance
from secret_sdk.core.coins import Coins, Coin
from datetime import datetime

import config
from dependencies import get_async_secret_client
from models import AdsForGasRequest
from services.tx_queue import get_tx_queue

router = APIRouter()

# Cache for pending rewards (address -> list of transaction_ids)
PENDING_REWARDS_CACHE = {}
REWARDS_CACHE_FILE = "ads_rewards.json"

# Cache for used transaction IDs to prevent replay attacks
USED_TRANSACTION_IDS = set()
USED_TX_FILE = "used_tx_ids.json"

# Google's public keys for SSV verification (cached)
GOOGLE_KEYS_CACHE = {}
GOOGLE_KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"
GOOGLE_KEYS_CACHE_DURATION = 86400  # 24 hours


def load_rewards_cache():
    """Load pending rewards cache from file."""
    global PENDING_REWARDS_CACHE
    try:
        if os.path.exists(REWARDS_CACHE_FILE):
            with open(REWARDS_CACHE_FILE, 'r') as f:
                PENDING_REWARDS_CACHE = json.load(f)
    except Exception as e:
        print(f"[AdsForGas] Could not load rewards cache: {e}", flush=True)
        PENDING_REWARDS_CACHE = {}


def save_rewards_cache():
    """Save pending rewards cache to file."""
    try:
        with open(REWARDS_CACHE_FILE, 'w') as f:
            json.dump(PENDING_REWARDS_CACHE, f)
    except Exception as e:
        print(f"[AdsForGas] Could not save rewards cache: {e}", flush=True)


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

        # Load the public key
        public_key = load_pem_public_key(pem_key.encode())

        # The message to verify is the query string up to &signature=
        # Remove signature and key_id from the query string for verification
        parts = query_string.split("&signature=")[0]
        message = parts.encode()

        # Decode the signature
        signature = base64.urlsafe_b64decode(signature_b64 + "==")  # Add padding

        # Verify using ECDSA with SHA256
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True

    except InvalidSignature:
        print(f"[AdsForGas] Invalid SSV signature", flush=True)
        return False
    except Exception as e:
        print(f"[AdsForGas] SSV verification error: {e}", flush=True)
        return False


async def check_registration_status(address: str, secret_async_client: AsyncLCDClient) -> bool:
    """Check if an address is registered on-chain."""
    try:
        query_msg = {"query_registration_status": {"address": address}}
        result = await secret_async_client.wasm.contract_query(
            config.REGISTRATION_CONTRACT, query_msg, config.REGISTRATION_HASH
        )
        return result.get("registration_status", False)
    except Exception as e:
        print(f"[AdsForGas] Error checking registration status: {e}", flush=True)
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

        # Get the full query string for signature verification
        query_string = str(request.url.query)

        # Parse query parameters
        params = dict(request.query_params)
        print(f"[AdsForGas] Params: {params}", flush=True)

        ad_unit = params.get("ad_unit", "")
        custom_data = params.get("custom_data", "")  # User's wallet address
        reward_amount = params.get("reward_amount", "1")
        reward_item = params.get("reward_item", "gas")
        timestamp = params.get("timestamp", "")
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
        if ad_unit and ad_unit != config.ADMOB_AD_UNIT_ID:
            print(f"[AdsForGas] Invalid ad unit: {ad_unit}", flush=True)
            return {"status": "error", "message": "Invalid ad unit"}

        # Fetch Google's public keys and verify signature
        keys = await fetch_google_keys()
        if not verify_ssv_signature(query_string, signature, key_id, keys):
            print(f"[AdsForGas] SSV signature verification failed", flush=True)
            return {"status": "error", "message": "Invalid signature"}

        # Mark transaction as used
        USED_TRANSACTION_IDS.add(transaction_id)
        save_used_tx_ids()

        # Add reward to pending rewards for this address
        load_rewards_cache()
        address = custom_data.strip()

        if address not in PENDING_REWARDS_CACHE:
            PENDING_REWARDS_CACHE[address] = []

        PENDING_REWARDS_CACHE[address].append({
            "transaction_id": transaction_id,
            "timestamp": timestamp,
            "reward_amount": reward_amount,
            "created_at": time.time()
        })
        save_rewards_cache()

        print(f"[AdsForGas] Reward verified for {address}, tx: {transaction_id}", flush=True)
        return {"status": "success"}

    except Exception as e:
        print(f"[AdsForGas] SSV callback error: {e}", flush=True)
        return {"status": "error", "message": str(e)}


@router.get("/ads-eligibility/{address}", summary="Check if user can claim gas from ads")
async def check_ads_eligibility(
    address: str,
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client)
):
    """
    Check if a user is eligible to claim gas (registered and has pending rewards).
    """
    try:
        load_rewards_cache()

        # Check if user is registered
        is_registered = await check_registration_status(address, secret_async_client)

        # Check for pending rewards
        pending_rewards = PENDING_REWARDS_CACHE.get(address, [])
        has_pending_rewards = len(pending_rewards) > 0

        return {
            "eligible": is_registered and has_pending_rewards,
            "registered": is_registered,
            "pending_rewards": len(pending_rewards),
            "ad_unit_id": config.ADMOB_AD_UNIT_ID
        }

    except Exception as e:
        print(f"[AdsForGas] Error checking eligibility: {e}", flush=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error checking eligibility: {str(e)}"
        )


@router.post("/ads-claim-gas", summary="Claim gas after watching an ad")
async def claim_gas_from_ad(
    req: AdsForGasRequest,
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client)
):
    """
    Claims gas allowance after a user has watched a rewarded ad.
    Requires the user to be registered and have a pending verified reward.
    """
    try:
        address = req.address
        reward_token = req.reward_token  # Transaction ID from the ad callback

        load_rewards_cache()

        # Check if user is registered
        is_registered = await check_registration_status(address, secret_async_client)
        if not is_registered:
            raise HTTPException(
                status_code=403,
                detail="User must be registered to claim gas"
            )

        # Check for pending rewards
        pending_rewards = PENDING_REWARDS_CACHE.get(address, [])
        if not pending_rewards:
            raise HTTPException(
                status_code=400,
                detail="No pending rewards. Please watch an ad first."
            )

        # Find and remove the matching reward
        reward_found = None
        for i, reward in enumerate(pending_rewards):
            if reward["transaction_id"] == reward_token:
                reward_found = pending_rewards.pop(i)
                break

        if not reward_found:
            # If no specific token match, use the oldest reward
            reward_found = pending_rewards.pop(0)

        # Update cache
        if pending_rewards:
            PENDING_REWARDS_CACHE[address] = pending_rewards
        else:
            del PENDING_REWARDS_CACHE[address]
        save_rewards_cache()

        # Grant gas allowance via transaction queue
        tx_queue = get_tx_queue()

        # Check granter balance
        balance = await secret_async_client.bank.balance(tx_queue.wallet_address)
        uscrt_coin = (balance[0] if balance else Coins()).get("uscrt")
        if not uscrt_coin or int(uscrt_coin.amount) < 2000000:
            raise HTTPException(
                status_code=503,
                detail="Service temporarily unavailable due to insufficient balance"
            )

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

        # Submit through transaction queue
        tx_result = await tx_queue.submit(
            msg_list=[grant_msg],
            gas=200000,
            memo="Ads for gas grant",
            wait_for_confirmation=False
        )

        if not tx_result.success:
            raise HTTPException(
                status_code=500,
                detail=f"Grant transaction failed: {tx_result.error}"
            )

        print(f"[AdsForGas] Gas allowance granted to {address}, tx: {tx_result.tx_hash}", flush=True)

        return {
            "success": True,
            "message": "Gas allowance granted successfully",
            "tx_hash": tx_result.tx_hash,
            "allowance_amount": "0.2 SCRT",
            "expires_at": datetime.fromtimestamp(expiration_time_in_seconds).isoformat(),
            "remaining_rewards": len(PENDING_REWARDS_CACHE.get(address, []))
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[AdsForGas] Error claiming gas: {e}", flush=True)
        raise HTTPException(
            status_code=500,
            detail=f"An internal server error occurred: {str(e)}"
        )


# Initialize caches on module load
load_rewards_cache()
load_used_tx_ids()
