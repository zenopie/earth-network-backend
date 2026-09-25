"""Configuration for the ads-for-gas service.

Everything the service needs comes from the environment; see example.env. The
only secret is GAS_WALLET_MNEMONIC, the hot key the dust is sent from.
"""
import os

from dotenv import load_dotenv

load_dotenv()

# --- HTTP ---
PORT = int(os.getenv("PORT", "8000"))

# --- earth chain ---
# cosmpy takes a scheme-prefixed URL: "rest+http://host:1317" or
# "grpc+http://host:9090". REST is the safer default — a node exposing only the
# API port is a supported deployment, and that is what the wallet apps use too.
EARTH_NODE_URL = os.getenv("EARTH_NODE_URL", "rest+http://localhost:1317")
EARTH_CHAIN_ID = os.getenv("EARTH_CHAIN_ID", "earth-1")
EARTH_PREFIX = os.getenv("EARTH_PREFIX", "earth")
EARTH_DENOM = os.getenv("EARTH_DENOM", "uerth")
EARTH_GAS_PRICE = float(os.getenv("EARTH_GAS_PRICE", "0.025"))

# The hot key the dust comes from. No default: refusing to start beats sending
# from a key nobody meant to use.
GAS_WALLET_MNEMONIC = os.getenv("GAS_WALLET_MNEMONIC", "")

# How much a verified ad view is worth, in uerth.
#
# This has to do two jobs: materialise the account (an address with no on-chain
# account cannot sign anything at all — the ante handler rejects it with
# "account does not exist", regardless of who pays the fee), and cover the gas
# for the transaction the user is trying to make. Registration is the expensive
# one at ~400k gas, so at 0.025 uerth/gas that is ~10,000 uerth; 50,000 leaves
# room for a few follow-up transactions before they are self-funding.
DUST_UERTH = int(os.getenv("DUST_UERTH", "50000"))

# --- AdMob ---
# The rewarded ad units that may trigger a grant.
#
# Plural, because an ad unit belongs to one platform and both apps call this one
# backend: Android's unit will never serve on iOS and vice versa. Comma-separate
# them. A single value still works, which is what every existing deployment has.
#
# Google sends the bare numeric id in the callback, not the full `ca-app-pub-…/…`
# form, so each entry is reduced to the part after the last slash and compared
# against that. Writing either form in the environment is therefore fine.
ADMOB_AD_UNIT_IDS = frozenset(
    unit.rsplit("/", 1)[-1]
    for unit in (u.strip() for u in os.getenv("ADMOB_AD_UNIT_ID", "").split(","))
    if unit
)

# How far a callback's signed timestamp may sit from now, in seconds. Replay
# protection is the transaction_id table; this bounds how long a captured
# callback stays worth anything should that table ever be lost, and refuses one
# stamped in the future outright. Wide enough for Google's delivery retries.
SSV_MAX_AGE_SECONDS = int(os.getenv("SSV_MAX_AGE_SECONDS", "3600"))
SSV_MAX_FUTURE_SECONDS = int(os.getenv("SSV_MAX_FUTURE_SECONDS", "300"))

# Google's rotating public keys for Server-Side Verification.
GOOGLE_SSV_KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"
GOOGLE_SSV_KEYS_TTL = 86400  # 24h

# --- storage ---
# Replay protection for SSV transaction ids.
STATE_DB = os.getenv("STATE_DB", "ads_for_gas.db")
