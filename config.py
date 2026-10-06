"""Configuration for the backend: gas grants and the privacy indexer.

Everything the service needs comes from the environment; see example.env. The
only secret is GAS_WALLET_MNEMONIC, the hot key the dust is sent from.
"""
import os

from dotenv import load_dotenv

load_dotenv()

# --- HTTP ---
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
# Of those places, how many only a priority check may take: a new passport
# whose DSC commitment the chain already holds registrations from
# (services/knowndsc, refreshed every KNOWN_DSC_REFRESH_SECONDS).
GAS_CHECK_RESERVED_WAITING = int(os.getenv("GAS_CHECK_RESERVED_WAITING", "5"))
KNOWN_DSC_REFRESH_SECONDS = float(os.getenv("KNOWN_DSC_REFRESH_SECONDS", "600"))

# Where MsgRegister's passport proof keeps its public inputs: personhood params
# nullifier_index, address_index, current_date_index and idc_index (earth-1
# genesis: 2, 1, 0, 4), and current_date_max_skew_seconds (172800). /gas/register reads them to
# refuse a replay, a proof bound to other notes, or a stale date before it
# spends a gas-check on the request. They must match the chain's params: a
# wrong index only makes this backend refuse or mis-key, never the chain
# accept, and a nullifier that differs from gas-check's answers 503.
PASSPORT_NULLIFIER_INDEX = int(os.getenv("PASSPORT_NULLIFIER_INDEX", "2"))
PASSPORT_ADDRESS_INDEX = int(os.getenv("PASSPORT_ADDRESS_INDEX", "1"))
PASSPORT_CURRENT_DATE_INDEX = int(os.getenv("PASSPORT_CURRENT_DATE_INDEX", "0"))
# dsc_key_index (earth-1: 3): the DSC commitment the reserved lane looks up.
PASSPORT_DSC_KEY_INDEX = int(os.getenv("PASSPORT_DSC_KEY_INDEX", "3"))
# idc_index (earth-1: 4): the identity commitment the circuit computes from the
# prover's id_secret. The chain refuses a proof whose idc input is not
# MsgRegister.idc (ErrBadPublicInputs 1103); /gas/register refuses it 400 first.
PASSPORT_IDC_INDEX = int(os.getenv("PASSPORT_IDC_INDEX", "4"))
PASSPORT_DATE_MAX_SKEW_SECONDS = int(os.getenv("PASSPORT_DATE_MAX_SKEW_SECONDS", "172800"))

# Per-client limits on /gas/register (services/ratelimit): requests per sliding
# window, and one gas-check in flight per client. A client is an IPv4 address
# or an IPv6 prefix of REGISTER_IPV6_PREFIX bits (48: a VPS host hands one
# customer a /48, 65536 /64s; 56 or 64 are looser). Its
# address is CF-Connecting-IP when TRUST_CF_CONNECTING_IP is on — right only
# when Cloudflare is the sole ingress, as on the Akash lease (tunnel-only,
# where deploy.yaml turns it on). Off by default: anywhere else the header is
# the client's to choose.
TRUST_CF_CONNECTING_IP = os.getenv("TRUST_CF_CONNECTING_IP", "false").lower() == "true"
REGISTER_IP_MAX_PER_WINDOW = int(os.getenv("REGISTER_IP_MAX_PER_WINDOW", "10"))
REGISTER_IP_WINDOW_SECONDS = float(os.getenv("REGISTER_IP_WINDOW_SECONDS", "3600"))
REGISTER_IPV6_PREFIX = int(os.getenv("REGISTER_IPV6_PREFIX", "48"))
# Clients remembered at once, least recently seen evicted first. One small
# fixed-size entry each (~200 bytes with the table's own overhead).
REGISTER_IP_MAX_TRACKED = int(os.getenv("REGISTER_IP_MAX_TRACKED", "20000"))
# Refusal budgets (services/ratelimit): gas-check refusals that cost a proof
# verification ("invalid registration proof"; cap, DSC and binding refusals
# never count), per minute, per DSC commitment, per issuing country and
# network-wide. Past one, a request under it is queued only with a proof of
# work at POW_SHED_BITS (428 without). 0 turns that budget off.
# The network's is set by what the lease can verify (audit-5 M3): checks
# run one at a time, and one earthd run on the 0.1-CPU lease (Go start-up,
# remote store reads, the verifier) is roughly ten seconds of wall time, so
# about six verifications a minute at most. A budget above that (it was 30)
# never trips; at 5, junk that keeps the verifier busy sheds the network.
REGISTER_REFUSALS_PER_DSC_PER_MINUTE = int(os.getenv("REGISTER_REFUSALS_PER_DSC_PER_MINUTE", "3"))
REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE = int(os.getenv("REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE", "4"))
REGISTER_REFUSALS_PER_MINUTE = int(os.getenv("REGISTER_REFUSALS_PER_MINUTE", "5"))
REGISTER_REFUSAL_KEYS_TRACKED = int(os.getenv("REGISTER_REFUSAL_KEYS_TRACKED", "10000"))
# Every gas-check refusal (either lane, cheap ones included; not a signer's
# or country's daily cap) also counts against its client: this many in the
# window (sliding) and the client's requests are queued only with a proof of
# work at POW_SHED_BITS (428 without) until they age out (audit-5 M3,
# audit-6 M1). Counted per IPv4 address or IPv6 /REGISTER_CLIENT_REFUSAL_IPV6_PREFIX
# (64: one subscriber, where a carrier's /48 holds many). 0 turns it off.
REGISTER_CLIENT_REFUSALS_PER_WINDOW = int(os.getenv("REGISTER_CLIENT_REFUSALS_PER_WINDOW", "3"))
REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS = float(os.getenv("REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS", "3600"))
REGISTER_CLIENT_REFUSAL_IPV6_PREFIX = int(os.getenv("REGISTER_CLIENT_REFUSAL_IPV6_PREFIX", "64"))

# Proof of work (services/pow; the spec wallets implement is in its module
# doc and the README): SHA-256 leading zero bits. Required for the reserved
# lane (POW_RESERVED_BITS) and while a request's refusal budget is spent
# (POW_SHED_BITS), plus up to POW_LOAD_EXTRA_BITS as the gas-check queue
# fills, never above POW_MAX_BITS. 2^20 hashes is ~1 s natively on a phone,
# a few seconds in a browser.
POW_RESERVED_BITS = int(os.getenv("POW_RESERVED_BITS", "16"))
POW_SHED_BITS = int(os.getenv("POW_SHED_BITS", "20"))
POW_LOAD_EXTRA_BITS = int(os.getenv("POW_LOAD_EXTRA_BITS", "2"))
POW_MAX_BITS = int(os.getenv("POW_MAX_BITS", "22"))
POW_MAX_AGE_SECONDS = int(os.getenv("POW_MAX_AGE_SECONDS", "600"))
POW_MAX_TRACKED = int(os.getenv("POW_MAX_TRACKED", "100000"))

# Rolling 24-hour payout limit for /gas/register. A grant needs a passport the
# chain would register and is once per passport per month, so this bounds
# what a run of fresh (or stolen) passports can drain from the hot wallet.
REGISTER_GRANT_MAX_PER_DAY = int(os.getenv("REGISTER_GRANT_MAX_PER_DAY", "500"))
# The same for switches (gas-check's "switched": a passport already
# registered moving to a new identity), counted apart so holders re-drawing
# a grant every 30 days by switching cannot spend the cap new registrants
# need (audit-4 B4). 0 pays no switch grants.
REGISTER_SWITCH_GRANT_MAX_PER_DAY = int(os.getenv("REGISTER_SWITCH_GRANT_MAX_PER_DAY", "100"))

# Seconds any one request to the chain's REST endpoint may take. Sends are
# serialised, so without a bound a single hung request stalls every payout.
CHAIN_HTTP_TIMEOUT = float(os.getenv("CHAIN_HTTP_TIMEOUT", "15"))
# /health serves the hot wallet's balance as read this often in the
# background (services/health), cacheable for as long.
HEALTH_REFRESH_SECONDS = float(os.getenv("HEALTH_REFRESH_SECONDS", "30"))

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
# The handle directory ({base}/handles): read from the chain's Handles query
# this many a page (the chain's maximum is 1000), again at least every
# HANDLES_MAX_AGE_SECONDS of block time, and refused past HANDLES_MAX_ENTRIES.
# A re-read is at most every HANDLES_MIN_REFRESH_BLOCKS blocks (anyone can
# put a handle event in every block), streamed page by page into SQLite
# (memory: one page), each page parsed off the event loop (audit-5 L4). The
# cap bounds the CPU of one re-read on the 0.1-CPU lease (~60 ms a page of
# 1000 there, so ~12 s of worker-thread time at 200k). Past
# HANDLES_STALE_BLOCKS behind a handle event, /privacy marks the directory
# stale (audit-5 L5).
HANDLES_QUERY_LIMIT = int(os.getenv("HANDLES_QUERY_LIMIT", "1000"))
HANDLES_MAX_AGE_SECONDS = int(os.getenv("HANDLES_MAX_AGE_SECONDS", "3600"))
HANDLES_MAX_ENTRIES = int(os.getenv("HANDLES_MAX_ENTRIES", "200000"))
HANDLES_MIN_REFRESH_BLOCKS = int(os.getenv("HANDLES_MIN_REFRESH_BLOCKS", "10"))
HANDLES_STALE_BLOCKS = int(os.getenv("HANDLES_STALE_BLOCKS", "30"))
# Page sizes for the /privacy streams (routers/privacy, audit-4 B3): limit
# must be one of PRIVACY_PAGE_SIZES (each at most PRIVACY_PAGE_MAX), and a
# position/index cursor a multiple of it, so every wallet asks for the same
# few URLs and the CDN keeps one copy of each page.
PRIVACY_PAGE_DEFAULT = int(os.getenv("PRIVACY_PAGE_DEFAULT", "1000"))
PRIVACY_PAGE_MAX = int(os.getenv("PRIVACY_PAGE_MAX", "1000"))
PRIVACY_PAGE_SIZES = tuple(int(x) for x in os.getenv("PRIVACY_PAGE_SIZES", "100,1000").split(",") if x.strip())
# What reaches the origin under /privacy (services/privacygate): at most
# PRIVACY_MAX_CONCURRENT responses in flight (503 past it; bounds memory on
# the 256 MiB lease), and per client (an IPv4 /32 or IPv6
# /REGISTER_IPV6_PREFIX, CF-Connecting-IP when trusted)
# PRIVACY_IP_MAX_PER_WINDOW requests in PRIVACY_IP_WINDOW_SECONDS (429). CDN
# hits never reach the origin, so these count only misses.
PRIVACY_MAX_CONCURRENT = int(os.getenv("PRIVACY_MAX_CONCURRENT", "4"))
PRIVACY_IP_MAX_PER_WINDOW = int(os.getenv("PRIVACY_IP_MAX_PER_WINDOW", "240"))
PRIVACY_IP_WINDOW_SECONDS = float(os.getenv("PRIVACY_IP_WINDOW_SECONDS", "60"))
# CORS on /privacy for the web wallet (services/privacygate): every response
# names this origin (fixed, so a CDN copy is right for every visitor), and a
# local dev origin (http://localhost[:port], http://127.0.0.1[:port]) gets
# its own back, uncached. No credentials. "" turns the fixed origin off.
PRIVACY_CORS_ORIGIN = os.getenv("PRIVACY_CORS_ORIGIN", "https://erth.network")
PRIVACY_CORS_LOCALHOST = os.getenv("PRIVACY_CORS_LOCALHOST", "true").lower() == "true"
