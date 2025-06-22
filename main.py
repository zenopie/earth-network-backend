# main.py

import os
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from Crypto.Cipher import DES3

# --- Create the FastAPI app instance ---
app = FastAPI(
    title="Earth Network BAC Service",
    description="A microservice to create the authentication command for ePassport Basic Access Control (BAC).",
    version="1.0.2", # Final version!
)

# --- Cryptographic Helper Functions for BAC ---

# --- NEW HELPER FUNCTION: DES Key Parity Adjustment ---
def adjust_key_parity(key: bytes) -> bytes:
    """
    Adjusts each byte of a DES key to have odd parity.
    The LSB of each byte is set or cleared to make the number of '1's odd.
    """
    adjusted_key = bytearray()
    for byte in key:
        # Count the number of set bits (1s)
        parity = bin(byte).count('1')
        # If parity is even, flip the last bit (LSB)
        if parity % 2 == 0:
            byte ^= 1
        adjusted_key.append(byte)
    return bytes(adjusted_key)

def derive_bac_keys(doc_num: str, dob: str, doe: str):
    # This function remains the same.
    mrz_info_str = (doc_num.ljust(9, '<') + dob + doe).upper()
    mrz_info_bytes = mrz_info_str.encode('utf-8')
    mrz_hash = hashlib.sha1(mrz_info_bytes).digest()
    key_seed = mrz_hash[:16]
    c1 = b'\x00\x00\x00\x01'
    k_enc = hashlib.sha1(key_seed + c1).digest()[:16]
    c2 = b'\x00\x00\x00\x02'
    k_mac = hashlib.sha1(key_seed + c2).digest()[:16]
    return k_enc, k_mac

def pad_iso9797_m2(data: bytes, block_size: int):
    # This function is correct and remains unchanged.
    padded = data + b'\x80'
    padding_len = block_size - (len(padded) % block_size)
    if padding_len == block_size:
        return padded
    return padded + (b'\x00' * padding_len)

def calculate_retail_mac(key: bytes, data: bytes):
    """
    Calculates the Retail-MAC using 2-key 3DES-CBC.
    We pass the 16-byte key directly; the library handles the K1-K2-K1 scheme.
    """
    # The key is the 16-byte Kmac directly.
    padded_data = pad_iso9797_m2(data, DES3.block_size)
    
    # The library will correctly interpret the 16-byte key as a 2-key 3DES key.
    cipher = DES3.new(key, DES3.MODE_CBC, iv=b'\x00'*8)
    
    encrypted = cipher.encrypt(padded_data)
    return encrypted[-8:]

# --- Pydantic Model (Unchanged) ---
class BacCommandRequest(BaseModel):
    passport_number: str
    date_of_birth: str
    date_of_expiry: str
    challenge_hex: str

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "BAC Service is running."}

@app.post("/create-bac-command")
async def create_bac_command(request: BacCommandRequest):
    print("--- Received BAC Command Request ---")
    try:
        k_enc_raw, k_mac_raw = derive_bac_keys(
            request.passport_number,
            request.date_of_birth,
            request.date_of_expiry
        )

        # --- FIX: Adjust key parity before using the keys ---
        k_enc = adjust_key_parity(k_enc_raw)
        k_mac = adjust_key_parity(k_mac_raw)
        
        print(f"Parity Adjusted Kenc: {k_enc.hex()}")
        print(f"Parity Adjusted Kmac: {k_mac.hex()}")

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