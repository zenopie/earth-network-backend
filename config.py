# /config.py
import os
import logging

# --- Environment & Ports ---
WEBHOOK_PORT = 8000
ALLOWED_ORIGINS = [
    "https://erth.network",
    # "http://localhost:3000"
]

# --- File Paths ---
ANALYTICS_FILE = "analyticsData.json"

# --- Secret Network ---
SECRET_LCD_URL = "https://lcd.erth.network"
SECRET_CHAIN_ID = "secret-4"
REGISTRATION_CONTRACT = "secret12q72eas34u8fyg68k6wnerk2nd6l5gaqppld6p"
REGISTRATION_HASH = "d8ef975b34982f3c1ef2feac1ea9503dd3bbc03c8c18c8e88e1889fc19c5c676"

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
UNIFIED_POOL_HASH = "2be409a0708a9e05155341ee3fe42a63bf2ff77b140942a2593767f5637bbf70"


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

WALLET_KEY = get_wallet_key()
logging.info("Wallet key loaded from environment variable.")

SECRET_AI_API_KEY = get_secret_ai_api_key()
logging.info("Secret AI API key loaded from environment variable.")

# --- CSCA Trust Store Configuration ---
# This URL points to a Master List file containing trusted CSCA certificates.
CSCA_URL = "https://raw.githubusercontent.com/zenopie/csca-trust-store/main/allowlist.ml"

def _download_and_extract_csca(url: str, dest_dir: str) -> str:
    """
    Thin wrapper that delegates downloading and extraction to tools.extract_csca.download_and_extract_csca.
    Kept for backward compatibility with existing callers/tests.
    """
    try:
        from tools.extract_csca import download_and_extract_csca as _tool_download_and_extract_csca  # [`python.imports()`](tools/extract_csca.py:1)
    except Exception as e:
        raise RuntimeError(f"tools.extract_csca.download_and_extract_csca unavailable: {e}")
    return _tool_download_and_extract_csca(url, dest_dir)
def get_csca_dir() -> str:
    """
    Ensures CSCA certificates are available and returns the directory path.
    Downloads and caches certificates from CSCA_URL on first run.
    Returns the path to the 'certs' subdirectory where individual certs are stored.
    """
    if not CSCA_URL:
        logging.warning("CSCA_URL not configured; chain validation will be disabled.")
        return ""
        
    # Use a local cache directory within the project
    cache_dir = os.path.join(os.path.dirname(__file__), ".csca_cache")
    certs_subdir = os.path.join(cache_dir, "certs")
    
    # Download and extract only if the certs directory doesn't exist
    if not os.path.isdir(certs_subdir):
        logging.info(f"CSCA cache not found. Downloading from {CSCA_URL}...")
        try:
            _download_and_extract_csca(CSCA_URL, cache_dir)
        except Exception as e:
            raise RuntimeError(f"FATAL: Failed to download or process CSCA trust store: {e}")

    if os.path.isdir(certs_subdir):
        return certs_subdir
    
    logging.warning(f"CSCA 'certs' subdirectory not found in {cache_dir}. Validation may fail.")
    return cache_dir # Fallback to the root cache dir

# --- CSCA Refresh Helper ---
def refresh_csca_cache() -> str:
    """
    Re-downloads the CSCA trust store into the cache directory and returns the certs path.
    """
    if not CSCA_URL:
        raise RuntimeError("CSCA_URL not configured; cannot refresh CSCA cache.")
    cache_dir = os.path.join(os.path.dirname(__file__), ".csca_cache")
    try:
        _download_and_extract_csca(CSCA_URL, cache_dir)
    except Exception as e:
        raise RuntimeError(f"Failed to refresh CSCA trust store: {e}")
    # Return the directory containing certs (if available)
    certs_subdir = os.path.join(cache_dir, "certs")
    return certs_subdir if os.path.isdir(certs_subdir) else cache_dir

# --- Initialize CSCA Trust Store on Application Startup ---
CSCA_DIR = get_csca_dir()
if CSCA_DIR and os.path.isdir(CSCA_DIR):
    logging.info(f"CSCA Trust Store is ready at: {CSCA_DIR}")

# --- Airdrop / Merkle Settings ---
# Configuration for weekly Merkle snapshot builder
# Set MERKLE_VALIDATOR to your validator operator address (secretvaloper...)
MERKLE_VALIDATOR = os.getenv("MERKLE_VALIDATOR", "")
MERKLE_DENOM = os.getenv("MERKLE_DENOM", "uscrt")
MERKLE_LIMIT = int(os.getenv("MERKLE_LIMIT", "1000"))
MERKLE_ODD_POLICY = os.getenv("MERKLE_ODD_POLICY", "duplicate")  # or "promote"
MERKLE_PROOFS = os.getenv("MERKLE_PROOFS", "all")  # "none" or "all"
MERKLE_TIMEOUT = int(os.getenv("MERKLE_TIMEOUT", "15"))
MERKLE_MAX_RETRIES = int(os.getenv("MERKLE_MAX_RETRIES", "3"))
MERKLE_INCLUDE_LEAF_HASHES = os.getenv("MERKLE_INCLUDE_LEAF_HASHES", "false").lower() in ("1", "true", "yes", "y")
# When true, run a one-time Merkle generation at application startup
MERKLE_RUN_ON_STARTUP = os.getenv("MERKLE_RUN_ON_STARTUP", "false").lower() in ("1", "true", "yes", "y")