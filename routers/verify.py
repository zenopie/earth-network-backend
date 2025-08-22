# /routers/verify.py
"""
FastAPI endpoint for ePassport Passive Authentication.
The heavy verification logic is extracted to tools.epassport_verifier.
"""
import logging
from fastapi import APIRouter, HTTPException

import config
from models import VerifyRequest
from tools.epassport_verifier import (
    EPassportVerifier,
    InvalidBase64Error,
    SODParseError,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.DEBUG)

router = APIRouter()

# Pre-load verifier with trust anchors from config.CSCA_DIR
CSCA_CERTS = EPassportVerifier.load_csca_from_dir(config.CSCA_DIR)
VERIFIER = EPassportVerifier(CSCA_CERTS)


@router.post("/verify", summary="Verify DG1 and SOD from an ePassport")
async def verify(req: VerifyRequest):
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
        result = VERIFIER.verify(req.dg1, req.sod)
        return result
    except InvalidBase64Error as e:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 input: {e}")
    except SODParseError as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse SOD or extract DSC: {e}")
    except RuntimeError as e:
        # Raised when no CSCA certificates are loaded or other runtime preconditions
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error during ePassport verification")
        raise HTTPException(status_code=500, detail="Internal server error during verification")