# main.py

import os
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# Required crypto libraries
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad

# --- Create the FastAPI app instance ---
app = FastAPI(
    title="Earth Network BAC Service",
    description="A microservice to create the authentication command for ePassport Basic Access Control (BAC).",
    version="1.0.0",
)

# --- Cryptographic Helper Functions for BAC ---

def derive_bac_keys(doc_num: str, dob: str, doe: str):
    """Derives Kenc and Kmac from the passport's MRZ info."""
    mrz_info_str = (doc_num.ljust(9, '<') + dob + doe).upper()
    mrz_info_bytes = mrz_info_str.encode('utf-8')
    mrz_hash = hashlib.sha1(mrz_info_bytes).digest()
    key_seed = mrz_hash[:16]
    c1 = b'\x00\x00\x00\x01'
    k_enc = hashlib.sha1(key_seed + c1).digest()[:16]
    c2 = b'\x00\x00\x00\x02'
    k_mac = hashlib.sha1(key_seed + c2).digest()[:16]
    return k_enc, k_mac

def calculate_retail_mac(key: bytes, data: bytes):
    """Calculates the Retail-MAC (a form of CMAC) using 3DES-CBC."""
    key_a, key_b = key[:8], key[8:16]
    mac_key = key_a + key_b + key_a
    padded_data = pad(data, DES3.block_size)
    cipher = DES3.new(mac_key, DES3.MODE_CBC, iv=b'\x00'*8)
    encrypted = cipher.encrypt(padded_data)
    return encrypted[-8:]

# --- Pydantic Model for the Request ---

class BacCommandRequest(BaseModel):
    passport_number: str = Field(..., description="The passport number from the MRZ.")
    date_of_birth: str = Field(..., description="Date of birth in YYMMDD format from the MRZ.")
    date_of_expiry: str = Field(..., description="Date of expiry in YYMMDD format from the MRZ.")
    challenge_hex: str = Field(..., description="The 8-byte challenge from the chip, hex-encoded.")

# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "BAC Service is running."}

@app.post("/create-bac-command")
async def create_bac_command(request: BacCommandRequest):
    """
    Creates the EXTERNAL AUTHENTICATE command for Basic Access Control (BAC).
    This is the only endpoint this service needs to provide for the mobile app to work.
    """
    print("--- Received BAC Command Request ---")
    try:
        k_enc, k_mac = derive_bac_keys(
            request.passport_number,
            request.date_of_birth,
            request.date_of_expiry
        )
        rnd_icc = bytes.fromhex(request.challenge_hex)
        rnd_ifd = os.urandom(8)
        k_ifd = os.urandom(16)
        s = rnd_ifd + rnd_icc + k_ifd
        cipher_enc = DES3.new(k_enc, DES3.MODE_ECB)
        e_ifd = cipher_enc.encrypt(s)
        m_ifd = calculate_retail_mac(k_mac, e_ifd)
        command_data = e_ifd + m_ifd
        apdu_command = (
            b'\x00\x82\x00\x00' +
            len(command_data).to_bytes(1, 'big') +
            command_data +
            b'\x08'
        )
        print("Successfully generated authentication command.")
        return {"command_hex": apdu_command.hex()}
    except Exception as e:
        print(f"Error creating BAC command: {e}")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred during the cryptographic process."
        )