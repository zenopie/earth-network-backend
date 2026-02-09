# /models.py
from pydantic import BaseModel
from typing import Optional

class RegisterRequest(BaseModel):
    address: str
    idImage: str
    selfieImage: str
    referredBy: Optional[str] = None

class VerifyRequest(BaseModel):
    """
    Request model for /verify endpoint.

    Fields:
    - dg1: base64-encoded DG1 bytes (required)
    - sod: base64-encoded SOD bytes (required)
    - address: user's address for registration (required)
    - referredBy: optional referrer address (optional)
    """
    dg1: str
    sod: str
    address: str
    referredBy: Optional[str] = None

class AdsForGasRequest(BaseModel):
    address: str
    reward_token: str  # The verification token from AdMob reward callback