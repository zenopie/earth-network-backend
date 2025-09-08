# /routers/faucet.py

import json
import logging
import os
import time
from fastapi import APIRouter, HTTPException, Depends
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.key.mnemonic import MnemonicKey
from secret_sdk.core.feegrant import MsgGrantAllowance
from secret_sdk.core.coins import Coins
from datetime import datetime

import config
from dependencies import get_async_secret_client
from models import FaucetGasRequest

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
router = APIRouter()

# Simple in-memory cache for tracking faucet usage (no database needed)
FAUCET_USAGE_CACHE = {}
FAUCET_CACHE_FILE = "faucet_usage.json"

def load_faucet_cache():
    """Load faucet usage cache from file if it exists."""
    global FAUCET_USAGE_CACHE
    try:
        if os.path.exists(FAUCET_CACHE_FILE):
            with open(FAUCET_CACHE_FILE, 'r') as f:
                FAUCET_USAGE_CACHE = json.load(f)
                logger.info(f"Loaded faucet cache with {len(FAUCET_USAGE_CACHE)} entries")
    except Exception as e:
        logger.warning(f"Could not load faucet cache: {e}")
        FAUCET_USAGE_CACHE = {}

def save_faucet_cache():
    """Save faucet usage cache to file."""
    try:
        with open(FAUCET_CACHE_FILE, 'w') as f:
            json.dump(FAUCET_USAGE_CACHE, f)
            logger.debug("Saved faucet cache to file")
    except Exception as e:
        logger.warning(f"Could not save faucet cache: {e}")

def can_use_faucet(address: str) -> bool:
    """Check if an address can use the faucet (once per week)."""
    now = time.time()
    last_usage = FAUCET_USAGE_CACHE.get(address, 0)
    week_in_seconds = 7 * 24 * 60 * 60
    return now - last_usage > week_in_seconds

def mark_faucet_used(address: str):
    """Mark that an address has used the faucet."""
    FAUCET_USAGE_CACHE[address] = time.time()
    save_faucet_cache()

async def check_registration_status(address: str, secret_async_client: AsyncLCDClient) -> bool:
    """Check if an address is registered on-chain."""
    try:
        query_msg = {"query_registration_status": {"address": address}}
        result = await secret_async_client.wasm.contract_query(
            config.REGISTRATION_CONTRACT, query_msg, config.REGISTRATION_HASH
        )
        return result.get("registration_status", False)
    except Exception as e:
        logger.error(f"Error checking registration status: {e}")
        return False

@router.post("/faucet-gas", summary="Grant gas allowance to registered users")
async def faucet_gas(
    req: FaucetGasRequest,
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client)
):
    """
    Grants a gas fee allowance to registered users who haven't used the faucet in the past week.
    Uses Cosmos feegrant module to give users gas credits for swapping tokens.
    """
    try:
        address = req.address
        
        # Load faucet usage cache
        load_faucet_cache()
        
        # Step 1: Check if user is registered
        is_registered = await check_registration_status(address, secret_async_client)
        if not is_registered:
            raise HTTPException(
                status_code=403, 
                detail="User must be registered to use gas faucet"
            )
        
        # Step 2: Check if user can use faucet (weekly cooldown)
        if not can_use_faucet(address):
            raise HTTPException(
                status_code=429, 
                detail="Gas faucet can only be used once per week"
            )
        
        # Step 3: Create wallet and grant gas allowance
        async_wallet = secret_async_client.wallet(MnemonicKey(config.WALLET_KEY))
        
        # Check granter balance
        balance = await secret_async_client.bank.balance(async_wallet.key.acc_address)
        uscrt_coin = (balance[0] if balance else Coins()).get("uscrt")
        if not uscrt_coin or int(uscrt_coin.amount) < 2000000:  # Need enough for grant + fees
            raise HTTPException(
                status_code=503, 
                detail="Faucet temporarily unavailable due to insufficient balance"
            )
        
        # Grant allowance: 0.2 SCRT (200000 uscrt) for gas with 1 hour expiration
        now_in_seconds = int(time.time())
        expiration_time_in_seconds = now_in_seconds + (1 * 3600)  # 1 hour
        
        grant_msg = MsgGrantAllowance(
            granter=async_wallet.key.acc_address,
            grantee=address,
            allowance={
                "expiration": {
                    "seconds": str(expiration_time_in_seconds)
                },
                "spend_limit": [
                    {
                        "amount": "200000",
                        "denom": "uscrt"
                    }
                ]
            }
        )
        
        # Broadcast the grant transaction
        tx = await async_wallet.create_and_broadcast_tx(
            msg_list=[grant_msg], 
            gas=200000, 
            memo="Gas faucet grant"
        )
        
        if tx.code != 0:
            raise HTTPException(
                status_code=500, 
                detail=f"Grant transaction failed: {tx.raw_log}"
            )
        
        # Mark faucet as used for this address
        mark_faucet_used(address)
        
        logger.info(f"Gas allowance granted to {address}, tx: {tx.txhash}")
        
        return {
            "success": True,
            "message": "Gas allowance granted successfully",
            "tx_hash": tx.txhash,
            "allowance_amount": "0.2 SCRT",
            "expires_at": datetime.fromtimestamp(expiration_time_in_seconds).isoformat(),
            "next_faucet_available": time.time() + (7 * 24 * 60 * 60)  # 1 week from now
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in faucet_gas: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"An internal server error occurred: {str(e)}"
        )

# Initialize cache on module load
load_faucet_cache()