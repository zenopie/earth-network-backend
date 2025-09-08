# /models.py
from pydantic import BaseModel
from typing import Optional, List, Dict

class RegisterRequest(BaseModel):
    address: str
    idImage: str
    selfieImage: str
    referredBy: Optional[str] = None

class ChatRequest(BaseModel):
    model: str
    messages: List[Dict]
    stream: bool = False

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

class FaucetGasRequest(BaseModel):
    address: str