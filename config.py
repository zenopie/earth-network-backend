"""Configuration for the backend: gas grants and the privacy indexer.

Everything the service needs comes from the environment; see example.env. The
only secret is GAS_WALLET_MNEMONIC, the hot key the dust is sent from.
"""
import os

from dotenv import load_dotenv

load_dotenv()

# --- HTTP ---
PORT = int(os.getenv("PORT", "8000"))
# Largest request body accepted, refused (413) before anything parses it
# (services/bodylimit). The largest real one, a /gas/register, is ~56 KiB.
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(64 * 1024)))

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

# How much one grant is worth, in uerth: the value of the fee note a new human
# pays MsgRegister's fee from. Registration is the expensive tx (the apps give
# it a 6M gas limit, 30,000 uerth at the validator's 0.005 uerth/gas); 100,000
# covers that with room to spare. Every later fee comes from the reward note.
DUST_UERTH = int(os.getenv("DUST_UERTH", "100000"))

# `earthd gas-check`: the chain release's binary, the node whose state it reads,
# and a writable home (earthd insists on one, and the service user has none).
EARTHD_BIN = os.getenv("EARTHD_BIN", "earthd")
EARTHD_HOME = os.getenv("EARTHD_HOME", "/tmp/earthd-home")
EARTH_RPC_URL = os.getenv("EARTH_RPC_URL", "https://rpc.erth.network:443")
GAS_CHECK_TIMEOUT = float(os.getenv("GAS_CHECK_TIMEOUT", "60"))
# Checks run one at a time (memory); beyond this many waiting, refuse with 503.
GAS_CHECK_MAX_WAITING = int(os.getenv("GAS_CHECK_MAX_WAITING", "20"))

# Where MsgRegister's passport proof keeps its public inputs: personhood params
# nullifier_index, address_index and current_date_index (earth-1 genesis: 2, 1,
# 0), and current_date_max_skew_seconds (172800). /gas/register reads them to
# refuse a replay, a proof bound to other notes, or a stale date before it
# spends a gas-check on the request. They must match the chain's params: a
# wrong index only makes this backend refuse or mis-key, never the chain
# accept, and a nullifier that differs from gas-check's answers 503.
PASSPORT_NULLIFIER_INDEX = int(os.getenv("PASSPORT_NULLIFIER_INDEX", "2"))
PASSPORT_ADDRESS_INDEX = int(os.getenv("PASSPORT_ADDRESS_INDEX", "1"))
PASSPORT_CURRENT_DATE_INDEX = int(os.getenv("PASSPORT_CURRENT_DATE_INDEX", "0"))
PASSPORT_DATE_MAX_SKEW_SECONDS = int(os.getenv("PASSPORT_DATE_MAX_SKEW_SECONDS", "172800"))

# Per-client limits on /gas/register (services/ratelimit): requests per sliding
# window, and one gas-check in flight per client. The client is
# CF-Connecting-IP when TRUST_CF_CONNECTING_IP is on — right only when
# Cloudflare is the sole ingress, as on the Akash lease (tunnel-only).
TRUST_CF_CONNECTING_IP = os.getenv("TRUST_CF_CONNECTING_IP", "true").lower() == "true"
REGISTER_IP_MAX_PER_WINDOW = int(os.getenv("REGISTER_IP_MAX_PER_WINDOW", "10"))
REGISTER_IP_WINDOW_SECONDS = float(os.getenv("REGISTER_IP_WINDOW_SECONDS", "3600"))
REGISTER_IP_MAX_TRACKED = int(os.getenv("REGISTER_IP_MAX_TRACKED", "100000"))

# Rolling 24-hour payout limit for /gas/register. A grant needs a passport the
# chain would register and is once per passport per month, so this bounds
# what a run of fresh (or stolen) passports can drain from the hot wallet.
REGISTER_GRANT_MAX_PER_DAY = int(os.getenv("REGISTER_GRANT_MAX_PER_DAY", "500"))

# Seconds any one request to the chain's REST endpoint may take. Sends are
# serialised, so without a bound a single hung request stalls every payout.
CHAIN_HTTP_TIMEOUT = float(os.getenv("CHAIN_HTTP_TIMEOUT", "15"))

# --- storage ---
# Replay protection for grant ids, and the history the daily caps count.
STATE_DB = os.getenv("STATE_DB", "ads_for_gas.db")

# --- privacy indexer ---
# Gas grants need the hot wallet; an indexer-only deployment turns them off
# and needs no mnemonic.
GAS_ENABLED = os.getenv("GAS_ENABLED", "true").lower() == "true"
# Follow the chain in this process. The /privacy API is served either way,
# from whatever INDEX_DB holds (another process may be the one writing it).
INDEXER_ENABLED = os.getenv("INDEXER_ENABLED", "false").lower() == "true"
INDEX_DB = os.getenv("INDEX_DB", "privacy_index.db")
# CometBFT RPC (not the LCD) the indexer reads blocks and /block_results
# from. It must keep block results from the start height on. earth-1's one
# node, the validator behind rpc.erth.network, is a full-history node
# (pruning=nothing, discard_abci_responses=false), so that is the default.
INDEXER_RPC_URL = os.getenv("INDEXER_RPC_URL", "https://rpc.erth.network:443")
INDEXER_RPC_TIMEOUT = float(os.getenv("INDEXER_RPC_TIMEOUT", "20"))
# The first height to index on an empty INDEX_DB; 0 = the node's earliest
# block. Ignored once the index holds blocks.
INDEXER_START_HEIGHT = int(os.getenv("INDEXER_START_HEIGHT", "0"))
INDEXER_BATCH = int(os.getenv("INDEXER_BATCH", "20"))
INDEXER_CONCURRENCY = int(os.getenv("INDEXER_CONCURRENCY", "8"))
INDEXER_POLL_SECONDS = float(os.getenv("INDEXER_POLL_SECONDS", "2"))
# Page size limits for the /privacy streams.
PRIVACY_PAGE_DEFAULT = int(os.getenv("PRIVACY_PAGE_DEFAULT", "1000"))
PRIVACY_PAGE_MAX = int(os.getenv("PRIVACY_PAGE_MAX", "5000"))
