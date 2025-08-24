# /routers/secret_query.py
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.exceptions import LCDResponseError

import config
from dependencies import get_async_secret_client

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

router = APIRouter()


class SecretQueryRequest(BaseModel):
    contract_address: str
    query: Dict[str, Any]
    code_hash: Optional[str] = None


@router.post("/contract_query", summary="Proxy contract query to Secret Network")
async def contract_query(
    req: SecretQueryRequest, secret_async_client: AsyncLCDClient = Depends(get_async_secret_client)
):
    """
    Proxy arbitrary contract query messages to the Secret Network LCD.

    Example payload from mobile:
    {
      "contract_address": "secret1...",
      "query": { "balance": { "address": "secret1..." } },
      "code_hash": "..."
    }
    """
    try:
        # Use the code_hash when provided (some contracts require it)
        if req.code_hash:
            result = await secret_async_client.wasm.contract_query(req.contract_address, req.query, req.code_hash)
        else:
            result = await secret_async_client.wasm.contract_query(req.contract_address, req.query)

        return {"success": True, "result": result}
    except LCDResponseError as e:
        logger.warning("LCDResponseError when querying contract: %s", e)
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error while proxying contract query")
        raise HTTPException(status_code=500, detail="Internal server error")