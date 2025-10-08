# /routers/verify.py
"""
FastAPI endpoint for ePassport Passive Authentication.
The heavy verification logic is extracted to tools.epassport_verifier.
When verification passes, registers the user with DG1 hash as identity.
"""
import asyncio
import hashlib
import json
import logging
from fastapi import APIRouter, HTTPException, Depends
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.exceptions import LCDResponseError
from secret_sdk.key.mnemonic import MnemonicKey
from secret_sdk.core.wasm import MsgExecuteContract
from secret_sdk.core.coins import Coins

import config
from models import VerifyRequest
from dependencies import get_async_secret_client, secret_client
from tools.epassport_verifier import (
    EPassportVerifier,
    InvalidBase64Error,
    SODParseError,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

router = APIRouter()

# Pre-load verifier with trust anchors from config.CSCA_DIR
CSCA_CERTS = EPassportVerifier.load_csca_from_dir(config.CSCA_DIR)
VERIFIER = EPassportVerifier(CSCA_CERTS)
print(f"🔐 Passport verifier initialized with {len(CSCA_CERTS)} CSCA certificates from {config.CSCA_DIR}")


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

            # Execute the registration transaction
            async_wallet = secret_async_client.wallet(MnemonicKey(config.WALLET_KEY))

            # Check balance before proceeding
            balance = await secret_async_client.bank.balance(async_wallet.key.acc_address)
            uscrt_coin = (balance[0] if balance else Coins()).get("uscrt")
            if not uscrt_coin or int(uscrt_coin.amount) < 1000000: # Example fee
                raise HTTPException(status_code=400, detail="Insufficient wallet balance for transaction fee.")

            # Create and broadcast the transaction
            message_object = {"register": {"address": req.address, "id_hash": identity_hash, "affiliate": req.referredBy}}
            msg = MsgExecuteContract(
                sender=async_wallet.key.acc_address, contract=config.REGISTRATION_CONTRACT,
                msg=message_object, code_hash=config.REGISTRATION_HASH,
                encryption_utils=secret_client.encrypt_utils
            )
            tx = await async_wallet.create_and_broadcast_tx(msg_list=[msg], gas=500000, memo="")
            if tx.code != 0:
                raise HTTPException(status_code=500, detail=f"Transaction broadcast failed: {tx.raw_log}")

            # Poll for transaction confirmation
            tx_info = None
            for i in range(30):  # Poll for ~30 seconds
                try:
                    tx_info = await secret_async_client.tx.tx_info(tx.txhash)
                    if tx_info:
                        break
                except LCDResponseError as e:
                    if "tx not found" in str(e).lower():
                        logger.info(f"Waiting for transaction confirmation... attempt {i+1}")
                        await asyncio.sleep(1)
                        continue
                    raise HTTPException(status_code=500, detail=f"Error polling for transaction: {e}")

            if not tx_info:
                raise HTTPException(status_code=504, detail="Transaction polling timed out. The transaction may have failed or is still pending.")

            if tx_info.code != 0:
                raise HTTPException(status_code=400, detail=f"Transaction failed on-chain: {tx_info.logs}")

            # Log successful registration without sensitive data
            print(f"✅ Registration transaction successful | TX: {tx_info.txhash}")

            # Return verification result with registration info
            result["registration"] = {
                "success": True,
                "identity_hash": identity_hash,
                "tx_hash": tx_info.txhash,
                "logs": tx_info.logs
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
        print(f"❌ VERIFY ERROR: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {type(e).__name__}")