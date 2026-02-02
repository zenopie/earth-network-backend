# /routers/verify.py
"""
FastAPI endpoint for ePassport Passive Authentication.
The heavy verification logic is extracted to tools.epassport_verifier.
When verification passes, registers the user with DG1 hash as identity.
"""
import hashlib
import json
import logging
import re
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.core.wasm import MsgExecuteContract
from secret_sdk.core.coins import Coins

import config
from models import VerifyRequest
from dependencies import get_async_secret_client
from services.tx_queue import get_tx_queue
from tools.epassport_verifier import (
    EPassportVerifier,
    InvalidBase64Error,
    SODParseError,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

router = APIRouter()


# Validation functions
def is_valid_secret_address(address: str) -> bool:
    """
    Validate that an address is a properly formatted Secret Network address.

    Secret Network addresses:
    - Start with "secret1"
    - Are bech32 encoded
    - Typically 45 characters long
    - Contain only lowercase alphanumeric characters (excluding '1', 'b', 'i', 'o')
    """
    if not address or not isinstance(address, str):
        return False

    # Basic format check: starts with "secret1" and has reasonable length
    if not address.startswith("secret1"):
        return False

    # Check length (bech32 addresses are typically 39-90 characters)
    if len(address) < 39 or len(address) > 90:
        return False

    # Bech32 character set (excludes '1', 'b', 'i', 'o' after the separator '1')
    bech32_pattern = r'^secret1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$'
    if not re.match(bech32_pattern, address):
        return False

    return True


async def check_referrer_registered(
    referrer_address: str,
    secret_async_client: AsyncLCDClient
) -> bool:
    """Check if a referrer address is registered on-chain."""
    try:
        query_msg = {"query_registration_status": {"address": referrer_address}}
        result = await secret_async_client.wasm.contract_query(
            config.REGISTRATION_CONTRACT,
            query_msg,
            config.REGISTRATION_HASH
        )
        is_registered = result.get("registration_status", False)

        if not is_registered:
            print(f"⚠️  Referrer address {referrer_address} is not registered", flush=True)

        return is_registered

    except Exception as e:
        print(f"❌ Error checking referrer registration status: {e}", flush=True)
        return False

# Pre-load verifier with trust anchors
CSCA_CERTS = EPassportVerifier.load_csca_from_dir(config.CSCA_DIR)
ADDITIONAL_CERTS = EPassportVerifier.load_csca_from_dir(config.ADDITIONAL_CSCA_DIR)
if ADDITIONAL_CERTS:
    CSCA_CERTS.extend(ADDITIONAL_CERTS)
VERIFIER = EPassportVerifier(CSCA_CERTS)
print(f"[Startup] Passport Verifier: {len(CSCA_CERTS)} CSCA certificates loaded", flush=True)


@router.post("/test-verify", summary="Test ePassport verification without blockchain registration")
async def test_verify(req: VerifyRequest):
    """
    Verifies ePassport DG1 and SOD but does NOT register on blockchain.
    Returns full verification details for testing purposes.
    """
    if not req.dg1:
        raise HTTPException(status_code=400, detail="Missing required field: dg1")
    if not req.sod:
        raise HTTPException(status_code=400, detail="Missing required field: sod")

    if not VERIFIER.csca_certs:
        raise HTTPException(
            status_code=500,
            detail="Server is misconfigured: No CSCA certificates loaded for trust validation.",
        )

    try:
        # Verify the ePassport and return the result
        result = VERIFIER.verify(req.dg1, req.sod)
        result["note"] = "Test mode: No blockchain transaction performed"
        return result

    except InvalidBase64Error as e:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 input: {e}")
    except SODParseError as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse SOD or extract DSC: {e}")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error during ePassport test verification")
        print(f"❌ TEST-VERIFY ERROR: {type(e).__name__}: {str(e)}", flush=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {type(e).__name__}")


@router.post("/verify", summary="Verify DG1 and SOD from an ePassport and register user if valid")
async def verify(
    req: VerifyRequest,
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client)
):
    if not req.dg1:
        raise HTTPException(status_code=400, detail="Missing required field: dg1")
    if not req.sod:
        raise HTTPException(status_code=400, detail="Missing required field: sod")
    if not req.address:
        raise HTTPException(status_code=400, detail="Missing required field: address")

    # Validate user address format
    if not is_valid_secret_address(req.address):
        raise HTTPException(status_code=400, detail=f"Invalid address format: {req.address}")

    # Validate referral address if provided
    if req.referredBy:
        # Check referrer address format
        if not is_valid_secret_address(req.referredBy):
            raise HTTPException(status_code=400, detail=f"Invalid referrer address format: {req.referredBy}")

        # Check for self-referral
        if req.address.lower() == req.referredBy.lower():
            raise HTTPException(status_code=400, detail="Self-referral is not allowed")

        # Check if referrer is registered on-chain
        is_referrer_registered = await check_referrer_registered(req.referredBy, secret_async_client)
        if not is_referrer_registered:
            raise HTTPException(
                status_code=400,
                detail=f"Referrer address {req.referredBy} is not registered. Only registered users can refer others."
            )
        print(f"✅ Referral validated: {req.address} referred by {req.referredBy}", flush=True)

    if not VERIFIER.csca_certs:
        raise HTTPException(
            status_code=500,
            detail="Server is misconfigured: No CSCA certificates loaded for trust validation.",
        )

    try:
        # Step 1: Verify the ePassport
        result = VERIFIER.verify(req.dg1, req.sod)
        
        # Step 2: If verification failed, return the result without registration
        if not result["passive_authentication_passed"]:
            return result
            
        # Step 3: If verification passed, register the user with DG1 hash as identity
        dg1_hash = result["details"]["dg1_hash_integrity"]["dg1_calculated_sha256"]
        # Note: Not logging DG1 hash as it contains passport-derived data

        # Hash the DG1 with secret to break traceability
        combined = f"{dg1_hash}{config.DG1_HASH_SECRET}"
        identity_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        # Note: Not logging identity hash for privacy

        # TODO: Enable registration for production
        REGISTRATION_ENABLED = True  # Set to True to enable blockchain registration

        if REGISTRATION_ENABLED:
            # Check for existing registration on-chain
            logger.info("Checking for existing passport registration")
            query_msg = {"query_registration_status_by_id_hash": {"id_hash": identity_hash}}
            existing_registration = await secret_async_client.wasm.contract_query(
                config.REGISTRATION_CONTRACT, query_msg, config.REGISTRATION_HASH
            )
            if existing_registration.get("registration_status"):
                logger.info("Registration rejected: passport already registered")
                raise HTTPException(status_code=409, detail="This ePassport has already been registered.")

            # Execute the registration transaction via unified queue
            tx_queue = get_tx_queue()

            # Check balance before proceeding
            balance = await secret_async_client.bank.balance(tx_queue.wallet_address)
            uscrt_coin = (balance[0] if balance else Coins()).get("uscrt")
            if not uscrt_coin or int(uscrt_coin.amount) < 1000000:
                raise HTTPException(status_code=400, detail="Insufficient wallet balance for transaction fee.")

            # Build message object with optional affiliate field
            message_object = {
                "register": {
                    "address": req.address,
                    "id_hash": identity_hash
                }
            }
            if req.referredBy:
                message_object["register"]["affiliate"] = req.referredBy

            msg = MsgExecuteContract(
                sender=tx_queue.wallet_address,
                contract=config.REGISTRATION_CONTRACT,
                msg=message_object,
                code_hash=config.REGISTRATION_HASH,
                encryption_utils=tx_queue.encryption_utils
            )

            # Submit through the transaction queue (handles sequencing and confirmation)
            tx_result = await tx_queue.submit(msg_list=[msg], gas=500000, memo="")
            if not tx_result.success:
                if "timed out" in (tx_result.error or "").lower():
                    raise HTTPException(status_code=504, detail="Transaction polling timed out. The transaction may have failed or is still pending.")
                raise HTTPException(status_code=500, detail=f"Transaction failed: {tx_result.error}")

            # Log successful registration without sensitive data
            print(f"✅ Registration transaction successful | TX: {tx_result.tx_hash}", flush=True)

            # Return verification result with registration info
            result["registration"] = {
                "success": True,
                "identity_hash": identity_hash,
                "tx_hash": tx_result.tx_hash,
                "logs": tx_result.logs
            }
        else:
            # Registration disabled for testing
            logger.info("Registration transaction disabled for testing - returning verification result only")
            result["registration"] = {
                "disabled": True,
                "identity_hash": identity_hash,
                "message": "Registration disabled for testing"
            }
        return result
        
    except InvalidBase64Error as e:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 input: {e}")
    except SODParseError as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse SOD or extract DSC: {e}")
    except RuntimeError as e:
        # Raised when no CSCA certificates are loaded or other runtime preconditions
        raise HTTPException(status_code=500, detail=str(e))
    except HTTPException:
        # Re-raise HTTPException directly to let FastAPI handle it
        raise
    except Exception as e:
        logger.exception("Unexpected error during ePassport verification and registration")
        print(f"❌ VERIFY ERROR: {type(e).__name__}: {str(e)}", flush=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {type(e).__name__}")