# /routers/airdrop.py
"""
Airdrop API endpoints for ERTH Network.
The scheduled airdrop job is in scheduled_tasks/airdrop.py
"""
from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from scheduled_tasks.airdrop import latest_run_row, get_claim


# ------------- FastAPI Router -------------

router = APIRouter(prefix="/airdrop", tags=["Airdrop"])


class RunMeta(BaseModel):
    merkle_root: str
    generated_at: str
    denom: str
    validator: str
    total_addresses: int
    total_amount: str
    block_height: Optional[int] = None
    block_time: Optional[str] = None


class ClaimResponse(BaseModel):
    address: str
    amount: str
    denom: str
    merkle_root: str
    proof: List[str]
    run_generated_at: str
    block_height: Optional[int] = None
    block_time: Optional[str] = None


@router.get("/current/meta", response_model=RunMeta)
def get_current_meta():
    """
    Returns metadata for the latest Merkle run.
    """
    row = latest_run_row()
    if not row:
        raise HTTPException(status_code=404, detail="No merkle run found")
    return RunMeta(
        merkle_root=row["merkle_root"],
        generated_at=row["generated_at"],
        denom=row["denom"],
        validator=row["validator_address"],
        total_addresses=row["total_addresses"],
        total_amount=row["total_amount"],
        block_height=row["block_height"],
        block_time=row["block_time"],
    )


@router.get("/current/{address}", response_model=ClaimResponse)
def get_current_claim_endpoint(address: str):
    """
    Returns the claim information (amount, merkle root, proof) for a given address from the latest run.
    """
    row = latest_run_row()
    if not row:
        raise HTTPException(status_code=404, detail="No merkle run found")
    run_id = row["id"]
    claim = get_claim(run_id, address)
    if not claim:
        raise HTTPException(status_code=404, detail="Address not found in latest snapshot")
    proof_list = []
    try:
        proof_list = json.loads(claim["proof_json"] or "[]")
    except Exception:
        proof_list = []
    return ClaimResponse(
        address=address,
        amount=str(claim["amount"]),
        denom=row["denom"],
        merkle_root=row["merkle_root"],
        proof=proof_list,
        run_generated_at=row["generated_at"],
        block_height=row["block_height"],
        block_time=row["block_time"],
    )