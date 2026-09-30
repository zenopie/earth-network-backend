"""Configuration for the gas-grant service.

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

# How much one attested grant is worth, in uerth.
#
# This has to do two jobs: materialise the account (an address with no on-chain
# account cannot sign anything at all — the ante handler rejects it with
# "account does not exist", regardless of who pays the fee), and cover the gas
# for the transaction the user is trying to make. Registration is the expensive
# one: the apps give it a 6M gas limit, which at the validator's 0.005 uerth/gas
# is 30,000 uerth. 100,000 covers that with room for a few follow-ups.
DUST_UERTH = int(os.getenv("DUST_UERTH", "100000"))

# --- attestation ---
# iOS App Attest: the app id is TEAMID.bundle-id. An attestation names the app
# it was made for, so this is what stops another team's app minting grants.
IOS_APP_ID = os.getenv("IOS_APP_ID", "XD8VH8WKVX.network.erth.EarthWallet")
# Accept keys made in App Attest's development environment — a build run from
# Xcode. Still our team's signed app on a real device; TestFlight and the App
# Store use production. Turn off once nobody is testing from Xcode.
APP_ATTEST_ALLOW_DEVELOPMENT = os.getenv("APP_ATTEST_ALLOW_DEVELOPMENT", "true").lower() == "true"

# Android key attestation: the package the attestation must name, and the
# SHA-256 digests of the certificates our APKs are signed with, comma-separated
# hex (colons allowed, as keytool and Play Console print them). Include both the
# upload/release key and, if Play App Signing is on, Play's app-signing key: a
# Play install is signed with the latter, a sideloaded release with the former.
# Unset, /gas/android answers 503 and iOS is unaffected.
ANDROID_PACKAGE = os.getenv("ANDROID_PACKAGE", "network.erth.wallet")
ANDROID_SIGNING_CERT_SHA256 = frozenset(
    bytes.fromhex(d.replace(":", "").strip())
    for d in os.getenv("ANDROID_SIGNING_CERT_SHA256", "").split(",")
    if d.strip()
)
# Refuse phones with an unlocked bootloader or unverified boot. On such a phone
# the OS can lie to the secure hardware about which app is asking.
ANDROID_REQUIRE_LOCKED_BOOTLOADER = os.getenv("ANDROID_REQUIRE_LOCKED_BOOTLOADER", "true").lower() == "true"

# `earthd gas-check`: the chain release's binary, the node whose state it reads,
# and a writable home (earthd insists on one, and the service user has none).
EARTHD_BIN = os.getenv("EARTHD_BIN", "earthd")
EARTHD_HOME = os.getenv("EARTHD_HOME", "/tmp/earthd-home")
EARTH_RPC_URL = os.getenv("EARTH_RPC_URL", "https://rpc.erth.network:443")
GAS_CHECK_TIMEOUT = float(os.getenv("GAS_CHECK_TIMEOUT", "60"))
# Checks run one at a time (memory); beyond this many waiting, refuse with 503.
GAS_CHECK_MAX_WAITING = int(os.getenv("GAS_CHECK_MAX_WAITING", "20"))

# How long a challenge stays usable, and how many may be outstanding at once.
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
CHALLENGE_MAX_PENDING = int(os.getenv("CHALLENGE_MAX_PENDING", "10000"))

# Rolling 24-hour payout limits, per address and for the service as a whole.
# An attestation proves a real device, not a new human: one phone can attest
# for as many fresh addresses as it likes, so the daily cap is what bounds that.
GRANT_MAX_PER_ADDRESS_PER_DAY = int(os.getenv("GRANT_MAX_PER_ADDRESS_PER_DAY", "3"))
GRANT_MAX_PER_DAY = int(os.getenv("GRANT_MAX_PER_DAY", "500"))

# Seconds any one request to the chain's REST endpoint may take. Sends are
# serialised, so without a bound a single hung request stalls every payout.
CHAIN_HTTP_TIMEOUT = float(os.getenv("CHAIN_HTTP_TIMEOUT", "15"))

# --- storage ---
# Replay protection for grant ids, and the history the daily caps count.
STATE_DB = os.getenv("STATE_DB", "ads_for_gas.db")
