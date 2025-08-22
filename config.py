# /config.py
import os
import tempfile
import urllib.request
import shutil
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
REGISTRATION_HASH = "12fad89bbc7f4c9051b7b5fa1c7af1c17480dcdee4b962cf6cb6ff668da02667"

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

def _safe_filename(s: str) -> str:
    """Creates a filesystem-friendly filename from a string."""
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in s)[:200]

def _download_and_extract_csca(url: str, dest_dir: str) -> str:
    """
    Downloads and extracts CSCA certificates from a URL.
    - Saves the downloaded master list file to dest_dir.
    - If the file is a `.ml` (Master List), it parses the CMS structure and
      extracts all embedded certificates into a `certs` subdirectory.
    """
    os.makedirs(dest_dir, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp()
    os.close(tmp_fd)
    try:
        with urllib.request.urlopen(url) as resp, open(tmp_path, "wb") as out:
            shutil.copyfileobj(resp, out)

        fname = os.path.basename(urllib.request.urlparse(url).path) or "csca_masterlist.ml"
        target = os.path.join(dest_dir, fname)
        shutil.move(tmp_path, target)

        if fname.lower().endswith(".ml"):
            try:
                # Local import to avoid making asn1crypto a hard dependency if not used.
                import asn1crypto.cms as cms
                from cryptography import x509

                with open(target, "rb") as f:
                    content_info = cms.ContentInfo.load(f.read())
                
                if content_info['content_type'].native == 'signed_data':
                    signed_data = content_info['content']
                    certs_field = signed_data.get('certificates') or []
                    certs_dir = os.path.join(dest_dir, "certs")
                    os.makedirs(certs_dir, exist_ok=True)
                    
                    for idx, cert_choice in enumerate(certs_field):
                        if cert_choice.name != 'certificate':
                            continue
                        try:
                            cert_der = cert_choice.chosen.dump()
                            cert = x509.load_der_x509_certificate(cert_der)
                            subj = cert.subject.rfc4514_string()
                            subj_safe = _safe_filename(subj)
                            out_name = f"csca_{idx}_{subj_safe}.der"
                            with open(os.path.join(certs_dir, out_name), "wb") as cf:
                                cf.write(cert_der)
                        except Exception as e:
                            logging.warning(f"Skipping malformed certificate in master list: {e}")
                            continue
            except ImportError:
                logging.error("`asn1crypto` library not found. Please `pip install asn1crypto` to parse .ml files.")
            except Exception as e:
                logging.error(f"Failed to parse master list file '{fname}': {e}")
        return dest_dir
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

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