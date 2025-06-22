# main.py

import os
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from Crypto.Cipher import DES3
# We are removing the import for `pad` as we will implement it manually.

# --- Create the FastAPI app instance ---
app = FastAPI(
    title="Earth Network BAC Service",
    description="A microservice to create the authentication command for ePassport Basic Access Control (BAC).",
    version="1.0.1", # Version bump!
)

# --- Cryptographic Helper Functions for BAC ---

def derive_bac_keys(doc_num: str, dob: str, doe: str):
    # This function is correct and remains unchanged.
    mrz_info_str = (doc_num.ljust(9, '<') + dob + doe).upper()
    mrz_info_bytes = mrz_info_str.encode('utf-8')
    mrz_hash = hashlib.sha1(mrz_info_bytes).digest()
    key_seed = mrz_hash[:16]
    c1 = b'\x00\x00\x00\x01'
    k_enc = hashlib.sha1(key_seed + c1).digest()[:16]
    c2 = b'\x00\x00\x00\x02'
    k_mac = hashlib.sha1(key_seed + c2).digest()[:16]
    return k_enc, k_mac

# --- NEW HELPER FUNCTION: Correct Padding ---
def pad_iso9797_m2(data: bytes, block_size: int):
    """
    Applies ISO/IEC 9797-1 Padding Method 2.
    This involves appending a single '80' byte, then padding with '00'
    bytes until the length is a multiple of the block size.
    """
    # Append the mandatory '80' byte
    padded = data + b'\x80'
    # Calculate how many '00' bytes are needed
    padding_len = block_size - (len(padded) % block_size)
    if padding_len == block_size:
        # If it's already a multiple, no extra padding is needed
        return padded
    return padded + (b'\x00' * padding_len)


# --- UPDATED FUNCTION: calculate_retail_mac ---
def calculate_retail_mac(key: bytes, data: bytes):
    """Calculates the Retail-MAC using 3DES-CBC and correct ISO padding."""
    key_a, key_b = key[:8], key[8:16]
    mac_key = key_a + key_b + key_a
    
    # --- FIX: Use the correct padding scheme ---
    padded_data = pad_iso9797_m2(data, DES3.block_size)
    
    cipher = DES3.new(mac_key, DES3.MODE_CBC, iv=b'\x00'*8)
    encrypted = cipher.encrypt(padded_data)
    return encrypted[-8:]


# --- Pydantic Model (Unchanged) ---
class BacCommandRequest(BaseModel):
    passport_number: str
    date_of_birth: str
    date_of_expiry: str
    challenge_hex: str

# --- API Endpoints (Unchanged) ---
@app.get("/")
def read_root():
    return {"message": "BAC Service is running."}

@app.post("/create-bac-command")
async def create_bac_command(request: BacCommandRequest):
    print("--- Received BAC Command Request ---")
    try:
        k_enc, k_mac = derive_bac_keys(
            request.passport_number,
            request.date_of_birth,
            request.date_of_expiry
        )
        rnd_icc = bytes.fromhex(request.challenge_hex)
        rnd_ifd, k_ifd = os.urandom(8), os.urandom(16)
        s = rnd_ifd + rnd_icc + k_ifd
        cipher_enc = DES3.new(k_enc, DES3.MODE_ECB)
        e_ifd = cipher_enc.encrypt(s)
        m_ifd = calculate_retail_mac(k_mac, e_ifd)
        command_data = e_ifd + m_ifd
        apdu_command = (
            b'\x00\x82\x00\x00' +
            len(command_data).to_bytes(1, 'big') +
            command_data
        )
        print("Successfully generated authentication command.")
        return {"command_hex": apdu_command.hex()}
    except Exception as e:
        print(f"Error creating BAC command: {e}")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred during the cryptographic process."
        )