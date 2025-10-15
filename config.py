# /config.py
import os
import logging

# --- Environment & Ports ---
WEBHOOK_PORT = 8000
ALLOWED_ORIGINS = [
    "https://erth.network",
]

# --- File Paths ---
ANALYTICS_FILE = "analyticsData.json"

# --- Secret Network ---
SECRET_LCD_URL = "https://lcd.erth.network"
SECRET_CHAIN_ID = "secret-4"
REGISTRATION_CONTRACT = "secret12q72eas34u8fyg68k6wnerk2nd6l5gaqppld6p"
REGISTRATION_HASH = "e6f9a7a7a6060721b0cf511d78a423c216fb961668ceeb7289dc189a94a7b730"

# --- Secret AI / Ollama ---
SECRET_AI_URL = "https://secretai-rytn.scrtlabs.com:21434"
OLLAMA_MODEL = "gemma3:4b"

# --- Analytics & DeFi Contracts ---
TOKENS = {
    "ERTH": {
        "contract": "secret16snu3lt8k9u0xr54j2hqyhvwnx9my7kq7ay8lp",
        "hash": "638a3e1d50175fbcb8373cf801565283e3eb23d88a9b7b7f99fcc5eb1e6b561e",
        "decimals": 6,
    },
    "ANML": {
        "contract": "secret14p6dhjznntlzw0yysl7p6z069nk0skv5e9qjut",
        "hash": "638a3e1d50175fbcb8373cf801565283e3eb23d88a9b7b7f99fcc5eb1e6b561e",
        "decimals": 6,
    },
    "sSCRT": {
        "contract": "secret1k0jntykt7e4g3y88ltc60czgjuqdy4c9e8fzek",
        "hash": "af74387e276be8874f07bec3a87023ee49b0e7ebe08178c49d0a49c3c98ed60e",
        "decimals": 6,
        "coingeckoId": "secret",
    },
}
UNIFIED_POOL_CONTRACT = "secret1rj2phrf6x3v7526jrz60m2dcq58slyq2269kra"
UNIFIED_POOL_HASH = "58c616e3736ccaecbdb7293a60ca1f8b4d64a75559a1dee941d1292a489ae0ec"


# --- Key Loading ---
def get_wallet_key() -> str:
    """Loads the wallet mnemonic from the 'WALLET_KEY' environment variable."""
    key = os.getenv("WALLET_KEY")
    if not key:
        raise ValueError("FATAL: WALLET_KEY environment variable not set or is empty.")
    return key

def get_secret_ai_api_key() -> str:
    """Loads the Secret AI API key from the 'SECRET_AI_API_KEY' environment variable."""
    api_key = os.getenv("SECRET_AI_API_KEY")
    if not api_key:
        raise ValueError("FATAL: SECRET_AI_API_KEY environment variable not set or is empty.")
    return api_key

def get_dg1_hash_secret() -> str:
    """Loads the DG1 hash secret from the 'DG1_HASH_SECRET' environment variable."""
    secret = os.getenv("DG1_HASH_SECRET")
    if not secret:
        raise ValueError("FATAL: DG1_HASH_SECRET environment variable not set or is empty.")
    return secret

WALLET_KEY = get_wallet_key()
logging.info("Wallet key loaded from environment variable.")

SECRET_AI_API_KEY = get_secret_ai_api_key()
logging.info("Secret AI API key loaded from environment variable.")

DG1_HASH_SECRET = get_dg1_hash_secret()
logging.info("DG1 hash secret loaded from environment variable.")

# --- CSCA Trust Store Configuration ---
def get_csca_dir() -> str:
    """
    Ensures CSCA certificates are available and returns the directory path.
    Extracts from bundled master list (csca_masterlist/allowlist.ml) on first run.
    Returns the path to the 'certs' subdirectory where individual certs are stored.
    """
    cache_dir = os.path.join(os.path.dirname(__file__), ".csca_cache")
    certs_subdir = os.path.join(cache_dir, "certs")

    # If certs already exist, return them
    if os.path.isdir(certs_subdir):
        return certs_subdir

    # Extract from bundled master list
    bundled_ml = os.path.join(os.path.dirname(__file__), "csca_masterlist", "allowlist.ml")
    if not os.path.isfile(bundled_ml):
        raise RuntimeError(f"FATAL: Bundled CSCA master list not found at {bundled_ml}")

    logging.info(f"Extracting CSCA certificates from bundled master list: {bundled_ml}")
    try:
        from tools.extract_csca import extract_csca_ders, save_ders_to_dir
        with open(bundled_ml, 'rb') as f:
            ml_bytes = f.read()
        ders = extract_csca_ders(ml_bytes)
        os.makedirs(certs_subdir, exist_ok=True)
        count = save_ders_to_dir(ders, certs_subdir, prefix="csca")
        logging.info(f"Extracted {count} CSCA certificates from bundled master list")
        return certs_subdir
    except Exception as e:
        raise RuntimeError(f"FATAL: Failed to extract bundled CSCA master list: {e}")

# --- Initialize CSCA Trust Store on Application Startup ---
CSCA_DIR = get_csca_dir()
if CSCA_DIR and os.path.isdir(CSCA_DIR):
    logging.info(f"CSCA Trust Store is ready at: {CSCA_DIR}")

# --- Additional CSCA Certificates Directory ---
# For manually added certificates (e.g., Israel, Nigeria, etc. not in master lists)
ADDITIONAL_CSCA_DIR = os.path.join(os.path.dirname(__file__), "csca_additional")
if not os.path.exists(ADDITIONAL_CSCA_DIR):
    os.makedirs(ADDITIONAL_CSCA_DIR, exist_ok=True)
    logging.info(f"Created additional CSCA directory at: {ADDITIONAL_CSCA_DIR}")
    # Create README
    readme_path = os.path.join(ADDITIONAL_CSCA_DIR, "README.md")
    with open(readme_path, "w") as f:
        f.write("""# Additional CSCA Certificates

Place manually obtained CSCA certificates here in DER format (.der, .cer).

These certificates will be loaded in addition to the ICAO master list certificates.

**Usage:**
1. Download CSCA certificate (DER or CER format)
2. Save to this directory with a descriptive name (e.g., `csca_israel.der`)
3. Restart the application

**Format:** DER-encoded X.509 certificates
**File extensions:** .der, .cer, or any extension (will attempt to load all files)
""")

# --- Airdrop / Merkle Settings ---
# Configuration for weekly Merkle snapshot builder
# Set MERKLE_VALIDATOR to your validator operator address (secretvaloper...)
MERKLE_VALIDATOR = os.getenv("MERKLE_VALIDATOR", "")
# When true, run a one-time Merkle generation at application startup
MERKLE_RUN_ON_STARTUP = os.getenv("MERKLE_RUN_ON_STARTUP", "false").lower() in ("1", "true", "yes", "y")

# Airdrop contract configuration
AIRDROP_CONTRACT = "secret13yyyzlqn4wq7ue40axh09phufv6myej7qvtmkw"
AIRDROP_HASH = "8c49bfc1c0d26ff8ecd7b1f85599a1e60fba8afbe41293313a4ddcedbc1fb9c3"

# Staking contract configuration (for claiming allocations before airdrop)
STAKING_CONTRACT = "secret10ea3ya578qnz02rmr7adhu2rq7g2qjg88ry2h5"
STAKING_HASH = "f3890262cc071b02dbb14f4dbd3b240aca4b0776be896fc60cfd993db97357db"
AIRDROP_ALLOCATION_ID = 4