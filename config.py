# /config.py
import os
import logging

# --- Environment & Ports ---
WEBHOOK_PORT = 8000
ALLOWED_ORIGINS = [
    "https://erth.network",
    "http://localhost:3000",
]

# --- Secret Network ---
SECRET_LCD_URL = "https://lcd.erth.network"
SECRET_CHAIN_ID = "secret-4"

# Contract addresses and hashes - populated from registry on startup
REGISTRATION_CONTRACT = None
REGISTRATION_HASH = None

# --- Analytics & DeFi Contracts ---
# TOKENS - populated from registry on startup, with metadata
TOKENS = {
    "ERTH": {
        "contract": None,
        "hash": None,
        "decimals": 6,
    },
    "ANML": {
        "contract": None,
        "hash": None,
        "decimals": 6,
    },
    "SSCRT": {
        "contract": None,
        "hash": None,
        "decimals": 6,
        "coingeckoId": "secret",
    },
    "XMR": {
        "contract": "secret1uahwhw3rk2x8vx4963yxqw6nl8h9drk79kasfx",
        "hash": "83d3a35e92363d3ef743dec1e9f2e8b3a18f2c761fe44169f11b436648a21078",
        "decimals": 12,
        "coingeckoId": "monero",
    },
}
UNIFIED_POOL_CONTRACT = None
UNIFIED_POOL_HASH = None

# XMR bridge manager contract (handles mint/burn with on-chain tracking)
XMR_MINTER_CONTRACT = "secret130nl6yfwuzjmnuknwfccq7jl8qekl4kcz0ppap"
XMR_MINTER_HASH = "91bed2b7eac8ba8e29c89efc32fcf0d0d0352d75f945da9035bc2ac4fa1ac14d"


# --- Key Loading ---
def get_wallet_key() -> str:
    """Loads the wallet mnemonic from the 'WALLET_KEY' environment variable."""
    key = os.getenv("WALLET_KEY")
    if not key:
        raise ValueError("FATAL: WALLET_KEY environment variable not set or is empty.")
    return key

def get_dg1_hash_secret() -> str:
    """Loads the DG1 hash secret from the 'DG1_HASH_SECRET' environment variable."""
    secret = os.getenv("DG1_HASH_SECRET")
    if not secret:
        raise ValueError("FATAL: DG1_HASH_SECRET environment variable not set or is empty.")
    return secret

WALLET_KEY = get_wallet_key()
logging.info("Wallet key loaded from environment variable.")

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

# Airdrop contract configuration - populated from registry on startup
AIRDROP_CONTRACT = None
AIRDROP_HASH = None

# Staking contract configuration - populated from registry on startup
STAKING_CONTRACT = None
STAKING_HASH = None
AIRDROP_ALLOCATION_ID = 4


def init_contracts_from_registry(registry_contracts: dict, registry_tokens: dict):
    """
    Initialize contract addresses and hashes from the registry.
    Called from main.py during startup.

    Args:
        registry_contracts: Dict of contract names to {contract, hash}
        registry_tokens: Dict of token symbols to {contract, hash}
    """
    global REGISTRATION_CONTRACT, REGISTRATION_HASH
    global UNIFIED_POOL_CONTRACT, UNIFIED_POOL_HASH
    global AIRDROP_CONTRACT, AIRDROP_HASH
    global STAKING_CONTRACT, STAKING_HASH
    global TOKENS

    # Update registration contract
    if "registration" in registry_contracts:
        REGISTRATION_CONTRACT = registry_contracts["registration"]["contract"]
        REGISTRATION_HASH = registry_contracts["registration"]["hash"]

    # Update unified pool contract (registry calls it "exchange")
    if "exchange" in registry_contracts:
        UNIFIED_POOL_CONTRACT = registry_contracts["exchange"]["contract"]
        UNIFIED_POOL_HASH = registry_contracts["exchange"]["hash"]

    # Update airdrop contract
    if "airdrop" in registry_contracts:
        AIRDROP_CONTRACT = registry_contracts["airdrop"]["contract"]
        AIRDROP_HASH = registry_contracts["airdrop"]["hash"]

    # Update staking contract
    if "staking" in registry_contracts:
        STAKING_CONTRACT = registry_contracts["staking"]["contract"]
        STAKING_HASH = registry_contracts["staking"]["hash"]

    # Update token contracts
    for symbol in TOKENS.keys():
        if symbol in registry_tokens:
            TOKENS[symbol]["contract"] = registry_tokens[symbol]["contract"]
            TOKENS[symbol]["hash"] = registry_tokens[symbol]["hash"]


# --- AdMob Ads for Gas Configuration ---
ADMOB_APP_ID = "ca-app-pub-8662126294069074~6689630767"
ADMOB_AD_UNIT_ID = "ca-app-pub-8662126294069074/9040854138"

# --- Monero Bridge Configuration ---
# Remote Monero daemon (for wallet-rpc to connect to)
MONERO_DAEMON_HOST = os.getenv("MONERO_DAEMON_HOST", "node.moneroworld.com")
MONERO_DAEMON_PORT = os.getenv("MONERO_DAEMON_PORT", "18089")

# Monero wallet-rpc URL (runs in same container, managed by supervisord)
MONERO_WALLET_RPC_URL = os.getenv("MONERO_WALLET_RPC_URL", "http://127.0.0.1:18083")

# Wallet mnemonic (25 words)
MONERO_MNEMONIC = os.getenv("MONERO_MNEMONIC", "")

# Wallet password (for wallet file encryption)
MONERO_WALLET_PASSWORD = os.getenv("MONERO_WALLET_PASSWORD", "bridge123")

# Bridge settings
XMR_CONFIRMATION_THRESHOLD = int(os.getenv("XMR_CONFIRMATION_THRESHOLD", "20"))
# Restore height for wallet sync (set to recent block height for faster sync)
# Current mainnet height is ~3.3M, use a recent height for new wallets
MONERO_RESTORE_HEIGHT = int(os.getenv("MONERO_RESTORE_HEIGHT", "3300000"))

# Check if bridge is configured
MONERO_BRIDGE_ENABLED = bool(MONERO_MNEMONIC)

if MONERO_BRIDGE_ENABLED:
    logging.info(f"Monero bridge configured: wallet-rpc at {MONERO_WALLET_RPC_URL}")
else:
    logging.info("Monero bridge not configured (missing MONERO_MNEMONIC)")