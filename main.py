# main.py

from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Dict, Any

# --- Create the FastAPI app instance ---
app = FastAPI(
    title="Earth Network Verification API",
    description="Processes verification data from the mobile app.",
    version="1.0.0",
)

# --- Define the structure of the incoming request data ---
# This ensures the data sent from your mobile app is validated automatically.
class VerificationRequest(BaseModel):
    wallet_address: str = Field(..., description="The user's Secret Network wallet address.")
    passport_data: Dict[str, Any] = Field(..., description="Data extracted from the passport's NFC chip.")

# --- Define the API endpoint ---
@app.post("/verify")
async def process_verification(request: VerificationRequest):
    """
    Receives wallet address and passport data, then processes it.
    
    In a real application, this is where you would:
    1. Verify the cryptographic signature of the passport data.
    2. Check if the wallet address or passport has already been registered.
    3. Store the successful registration in a database.
    4. Return a success or failure response.
    """
    print("--- Received Verification Request ---")
    print(f"Wallet Address: {request.wallet_address}")
    print(f"Passport Data: {request.passport_data}")
    
    # TODO: Implement your core business logic here.
    # For now, we'll just simulate a successful processing.
    
    is_signature_valid = True # Placeholder for your verification logic

    if is_signature_valid:
        # TODO: Save to a database (e.g., PostgreSQL, MongoDB)
        
        return {
            "status": "success",
            "message": "Verification data received and processed successfully.",
            "registered_address": request.wallet_address,
        }
    else:
        return {
            "status": "error",
            "message": "Signature verification failed.",
        }

# --- A simple root endpoint to confirm the API is running ---
@app.get("/")
def read_root():
    return {"message": "Welcome to the Earth Network Verification API"}