# earth network backend

One FastAPI service with two jobs:

- **Gas grants.** A new human has no ERTH, and on the shielded chain a
  registration is an unsigned private tx that pays its fee from a shielded
  note. `POST /gas/register` funds that first note, once per passport in any
  30 days, for a registration the chain itself would accept. The registration
  mints a shielded reward that pays every later fee.
- **The privacy indexer.** Wallets never ask anyone about their own notes.
  They download every note commitment and ciphertext, every nullifier, every
  identity leaf and the stake, handle and slash-debt data, rebuild the trees
  locally and trial-decrypt. The indexer follows the chain into SQLite and
  serves that data as full-range streams under `/privacy`. There is no
  endpoint keyed by anything a wallet derives from its keys.

Either runs without the other (`GAS_ENABLED`, `INDEXER_ENABLED`).

How the design got here (audit rounds, findings, accepted risks) is in
[AUDIT_HISTORY.md](AUDIT_HISTORY.md). Finding ids such as `audit-5 M3` in
code comments refer to it.

## Layout

    main.py                 the app: middleware, routers, background tasks, GET /health
    config.py               every setting, from the environment (see example.env)
    entrypoint.py           container entrypoint: chown the state volume, drop root, exec uvicorn
    routers/gas.py          POST /gas/register, GET /gas/pow
    routers/privacy.py      the /privacy streams
    routers/circuits.py     GET /circuits/<variant>.json.gz: the passport circuits the wallets do not bundle
    circuits/               those circuits, gzipped (written by the mobile repo's circuits/tools/variants.py build)
    services/
      bodylimit.py          request body cap (413 before parsing)
      chain.py              the hot wallet: MsgShield of the dust, broadcast resolved by tx hash
      shielded_msg.py       earth.shielded.v1.MsgShield, built without the chain's protos
      gascheck.py           `earthd gas-check registration`, one at a time, two queue lanes
      ratelimit.py          per-client windows, refusal budgets, one check per client, signer lanes
      pow.py                the proof of work stamp
      dsccommit.py          a DSC certificate's chain commitment (x/pki/certs.DscCommitmentOf)
      knowndsc.py           the DSC commitments the chain holds registrations from
      replay.py             grant ids and the daily caps (SQLite, STATE_DB)
      health.py             the hot wallet balance, read in the background
      privacygate.py        /privacy admission: canonical URLs, CORS, rate, in-flight cap
      privacy/              the indexer: rpc, events (block parsing), store (SQLite),
                            handles (the Handles query), indexer (the loop), verify
      zk/                   Poseidon2, the Merkle, indexed and debt trees, zk/privacy derivations
    bin/                    deploy tools, tree verification, fixture and vector recorders
    deploy/akash/           the SDL and the Cloudflare setup
    tests/                  pytest, by feature (gas_*, privacy_*, handles, debt_rows, ...)

## Running

    pip install -r requirements.txt
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC, or set GAS_ENABLED=false
    uvicorn main:app --host 0.0.0.0 --port 8000

`/gas/register` needs `earthd` (the chain release's binary, `EARTHD_BIN`) and
a node to read state from (`EARTH_RPC_URL`); the image installs it. The
indexer runs inside the API process with `INDEXER_ENABLED=true`, or alone:

    python -m services.privacy.indexer

Tests need no chain: gas-check's verdict is stood in for, and recorded chain
blocks are replayed for the indexer.

    pip install -r requirements-dev.txt
    python -m pytest

One test (`test_gascheck_live`) runs the real command and is skipped unless
`EARTHD_BIN` and `GAS_CHECK_LIVE_MSG` (a MsgRegister JSON file) are set.

The image (`Dockerfile`) installs `requirements.lock` (the whole tree, hashed,
wheels only; regenerate with `bin/lock-requirements.py`) on a digest-pinned
`python:3.11-slim`, plus `earthd` at `EARTHD_VERSION`, checked against its
release sha256. It runs as an unprivileged user with the state volume at
`/app/state` (`STATE_DB`, `INDEX_DB`), uvicorn without access log or proxy
headers.

## Configuration

Everything comes from the environment; `example.env` lists every setting with
its default. The only secret the service reads is `GAS_WALLET_MNEMONIC`.

| group | settings |
|---|---|
| HTTP | `MAX_BODY_BYTES` (65536) |
| chain | `EARTH_NODE_URL` (cosmpy URL, `rest+https://...`), `EARTH_CHAIN_ID` (`earth-1`), `EARTH_PREFIX`, `EARTH_DENOM` (`uerth`), `EARTH_GAS_PRICE`, `CHAIN_HTTP_TIMEOUT` (15 s) |
| hot wallet | `GAS_WALLET_MNEMONIC` (required when `GAS_ENABLED`), `DUST_UERTH` (100000), `HEALTH_REFRESH_SECONDS` (30) |
| gas-check | `EARTHD_BIN`, `EARTHD_HOME`, `EARTH_RPC_URL` (CometBFT RPC), `GAS_CHECK_TIMEOUT` (60 s), `GAS_CHECK_MAX_WAITING` (20), `GAS_CHECK_RESERVED_WAITING` (5), `KNOWN_DSC_REFRESH_SECONDS` (600) |
| personhood params | `PASSPORT_NULLIFIER_INDEX` (2), `PASSPORT_ADDRESS_INDEX` (1), `PASSPORT_CURRENT_DATE_INDEX` (0), `PASSPORT_DSC_KEY_INDEX` (3), `PASSPORT_DATE_MAX_SKEW_SECONDS` (172800); the chain's genesis values, mirrored |
| per-client limits | `TRUST_CF_CONNECTING_IP` (false), `REGISTER_IP_MAX_PER_WINDOW` (10), `REGISTER_IP_WINDOW_SECONDS` (3600), `REGISTER_IPV6_PREFIX` (48), `REGISTER_IP_MAX_TRACKED` (20000) |
| refusal budgets | `REGISTER_REFUSALS_PER_DSC_PER_MINUTE` (3), `REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE` (4), `REGISTER_REFUSALS_PER_MINUTE` (5), `REGISTER_REFUSAL_KEYS_TRACKED` (10000), `REGISTER_CLIENT_REFUSALS_PER_WINDOW` (3), `REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS` (3600), `REGISTER_CLIENT_REFUSAL_IPV6_PREFIX` (64) |
| proof of work | `POW_RESERVED_BITS` (16), `POW_SHED_BITS` (20), `POW_LOAD_EXTRA_BITS` (2), `POW_MAX_BITS` (22), `POW_MAX_AGE_SECONDS` (600), `POW_MAX_TRACKED` (100000) |
| daily caps | `REGISTER_GRANT_MAX_PER_DAY` (500), `REGISTER_SWITCH_GRANT_MAX_PER_DAY` (100) |
| storage | `STATE_DB` (`ads_for_gas.db`), `INDEX_DB` (`privacy_index.db`) |
| indexer | `GAS_ENABLED` (true), `INDEXER_ENABLED` (false), `INDEXER_RPC_URL`, `INDEXER_RPC_TIMEOUT` (20), `INDEXER_START_HEIGHT` (0: the node's earliest), `INDEXER_BATCH` (20), `INDEXER_CONCURRENCY` (8), `INDEXER_POLL_SECONDS` (2) |
| handle directory | `HANDLES_QUERY_LIMIT` (1000), `HANDLES_MAX_AGE_SECONDS` (3600), `HANDLES_MAX_ENTRIES` (200000), `HANDLES_MIN_REFRESH_BLOCKS` (10), `HANDLES_STALE_BLOCKS` (30) |
| /privacy | `PRIVACY_PAGE_DEFAULT` (1000), `PRIVACY_PAGE_SIZES` (100,1000), `PRIVACY_PAGE_MAX` (1000), `PRIVACY_MAX_CONCURRENT` (4), `PRIVACY_IP_MAX_PER_WINDOW` (240), `PRIVACY_IP_WINDOW_SECONDS` (60), `PRIVACY_CORS_ORIGIN` (`https://erth.network`), `PRIVACY_CORS_LOCALHOST` (true) |

`TRUST_CF_CONNECTING_IP=true` is right only where Cloudflare is the sole
ingress (the Akash lease is tunnel-only and sets it); anywhere else the
header is the client's to choose. `.env` also holds three values only the
deploy tools read: `DSEQ`, `AKASH_API_KEY`, `TUNNEL_TOKEN`.

## Endpoints

    POST /gas/register                     a fee note for a registration the chain would accept
    GET  /gas/pow                          the proof of work /gas/register needs now
    GET  /health                           hot wallet balance and grants remaining
    GET  /circuits/<variant>.json.gz       a passport register circuit outside the wallets' bundle
    GET  /privacy/status                   which chain the index holds, and its stream base
    GET  /privacy/<chain_id>/<genesis>/... the streams (below)

`/gas/*` exists only with `GAS_ENABLED=true`. `/circuits` serves the 17
passport register circuits above the wallets' 2^18 tier (PASSPORT_COVERAGE.md
in the mobile repo), byte for byte as `circuits/` holds them; the wallets
inflate each one and refuse it unless it hashes to the sha256 their bundled
`passport_variants.json` pins, so the server is trusted for availability
only. FastAPI's `/docs` and
`/openapi.json` describe the request schemas.

### GET /health

    {"status": "ok", "wallet": "earth1...", "balance_uerth": N, "dust_uerth": 100000,
     "grants_remaining": N // dust_uerth, "read_at": unix}

`"status": "starting"` before the first read, `"degraded"` (and nothing else)
when the last read failed; `{"status": "ok", "gas": "disabled"}` without gas
grants. The balance is read in the background every `HEALTH_REFRESH_SECONDS`
and served from memory with `Cache-Control: public, max-age=30`; a request
never reaches the node. Alert on `grants_remaining`: when the hot wallet runs
dry every grant fails after the registration checks out.

## Gas grants

### POST /gas/register

The MsgRegister the app is about to broadcast, without its fee bundle (bytes
as standard base64, as proto JSON), plus where the gas goes:

    {"proof", "public_signals": [decimal strings], "signature_algorithm", "dsc_der",
     "idc", "pc_anml", "pc_erth", "ciphertext_anml", "ciphertext_erth",
     "affiliate_handle"?,                     // a referral: a live handle, "" or absent for none
     "pc_gas", "ciphertext_gas",              // the gas note's pc and its ciphertext
     "pow"?: {"ts": unix, "nonce": "..."}}    // see Proof of work

Every ciphertext is a note's amount-blind v2 ciphertext
(`zk/privacy.EncryptBlindNote`), exactly 177 bytes. `ciphertext_anml` and
`ciphertext_erth` are MsgRegister's own (the proof's binding covers them);
`ciphertext_gas` is the gas note's, carried on the `MsgShield`.
`affiliate_pc` / `affiliate_ciphertext` are not MsgRegister fields: a body
with either, even empty, is refused 400 with a message naming them (the chain
mints the referral note itself).

If the chain would accept the registration (`earthd gas-check registration`,
the chain's own code, proof verified here), the hot wallet shields
`DUST_UERTH` into a note to `pc_gas` with `ciphertext_gas`. The app then
broadcasts MsgRegister paying its fee from that note.

Answers are `{"status", "message", "tx_hash"?}`:

| code | when |
|---|---|
| 200 `success` | the gas note was shielded; `tx_hash` is the shield tx |
| 202 `pending` | broadcast, not seen within the wait; the grant stays claimed; `tx_hash` to watch |
| 400 | a check before gas-check failed (shape, binding, date, signer validity, `dsc_der` not the named signer, removed fields) |
| 403 | gas-check refused it: `message` carries the chain's reason |
| 409 | this passport was granted in the last 30 days |
| 413 | body over `MAX_BODY_BYTES` (before anything is parsed) |
| 422 | not a registration request (schema); `detail` lists the errors |
| 428 | a proof of work is needed or was not accepted; `pow: {"version", "bits"}` |
| 429 | per-client window, a check of this client already running, or the daily cap |
| 502 | the shield failed and moved nothing; the grant is released, retry |
| 503 | gas-check unavailable, the queue is full, or the node is misconfigured; retry |

### Grant rules

- **Once per passport in any 30 days**, sliding. A grant is recorded as
  `passport:<nullifier hex>:<YYYY-MM-DD>` (the nullifier is
  `public_signals[PASSPORT_NULLIFIER_INDEX]`, public on chain anyway) with its
  kind and time, and nothing else: no address, no pc, no tx hash. Any id
  under the passport's prefix in the last 30 days refuses another (409),
  checked before gas-check and again atomically with the insert. Rows older
  than 31 days are pruned.
- **Daily caps, by kind.** A *switch* (a passport already registered moving
  to a new identity; gas-check answers `switched`) counts only against
  `REGISTER_SWITCH_GRANT_MAX_PER_DAY`, a first registration only against
  `REGISTER_GRANT_MAX_PER_DAY`, each over the last 24 hours. Before gas-check
  a request is refused 429 only when both are spent; otherwise the kind's cap
  decides after the check. A switch can draw a grant every 30 days; capping
  switches apart keeps them from spending the first-registration cap.
- **Claim before sending.** The grant is claimed, then shielded. A failure
  before the post, a connection never made, a CheckTx refusal, or a tx found
  included-and-failed moved nothing: the claim is released (502). Any other
  failure after the post (a read timeout, a dropped connection, a proxy's
  non-200) is resolved by the tx hash, which is known before the post: found
  and successful is 200, not seen within the wait is 202 and the claim is
  kept, since the tx may still land.
- **Nullifier agreement.** gas-check reads the nullifier from the chain's
  own `nullifier_index`. If it differs from ours the request is 503 and
  nothing is claimed: `PASSPORT_NULLIFIER_INDEX` is misconfigured.
- **Logs** never tie a passport to its gas note: a grant logs only
  "registration gas note sent", a refusal only its kind, and errors pass
  through a filter that cuts hex and long decimal runs.
- **Sends are serialised.** One lock over the hot key's account sequence;
  one replica.

Accepted risks (reasons in AUDIT_HISTORY.md): a MsgRegister copied from the
mempool before its registrant asked for gas can claim that passport's grant
to another pc; whether the DSC is a trusted signer is gas-check's to decide,
not this service's.

### What runs before gas-check, in order

A proof verification is the expensive part (one at a time, ~120 MB), so
everything that can refuse a request without one runs first:

1. **Body size** over `MAX_BODY_BYTES` → 413 (`services/bodylimit`; a
   streamed body is cut off as it arrives).
2. **Per-client window**: `REGISTER_IP_MAX_PER_WINDOW` requests per
   `REGISTER_IP_WINDOW_SECONDS`, sliding, malformed bodies included → 429. A
   client is an IPv4 address or an IPv6 /`REGISTER_IPV6_PREFIX` (48); its
   address is `CF-Connecting-IP` when trusted, else the TCP peer. At most
   `REGISTER_IP_MAX_TRACKED` clients are tracked, least recently seen evicted.
3. **Schema**: field types and loose length caps → 422.
4. **Shape** (`MsgRegister.ValidateBasic`): base64; idc and pcs canonical
   32-byte field elements; proof 1..32 KiB; `dsc_der` 1..8 KiB; every
   ciphertext exactly 177 bytes; `signature_algorithm` 1..64 bytes; 1..16
   public signals, each a canonical decimal field element; a handle `a-z`,
   `0-9`, `-`, 3..32 characters, no leading or trailing dash → 400.
5. **Binding**: `public_signals[PASSPORT_ADDRESS_INDEX]` must equal
   `H(TAG_REG, Bytes(EARTH_CHAIN_ID), idc, pc_anml, Bytes(ciphertext_anml),
   pc_erth, Bytes(ciphertext_erth), affiliate)`, affiliate 0 or
   `H(TAG_AFFILIATE, Bytes(affiliate_handle))` (`services/zk/privacy`, pinned
   to the chain's Go vectors) → 400. Someone else's proof with notes of one's
   own, or a proof for another chain, stops here.
6. **Date**: `public_signals[PASSPORT_CURRENT_DATE_INDEX]` (YYMMDD, a real
   calendar date) within `PASSPORT_DATE_MAX_SKEW_SECONDS` + 10 min of now →
   400.
7. **Document signer validity**: a `dsc_der` outside its validity by more
   than 10 min → 400 (the chain's first check of the certificate; an expired
   signer is the registrant's circumstance and counts against no one).
8. **Replay** (409) and **both daily caps spent** (429), as above.
9. **Shedding and proof of work** (below) → 428.
10. **Reserved lane**: for a candidate with a proof of work, `dsc_der`'s DSC
    commitment must be the one `public_signals[PASSPORT_DSC_KEY_INDEX]` names
    → 400 otherwise.
11. **One check per client**: a client with a gas-check queued or running →
    429. The queue holds `GAS_CHECK_MAX_WAITING` → 503 past it.

### Refusal budgets and shedding

Junk with a forged binding passes every check above; only gas-check refuses
it. What a refusal costs:

- **Verification failures** (the chain's `invalid registration proof`, the
  only refusal that cost a proof verification) count per minute against the
  DSC commitment's budget (`REGISTER_REFUSALS_PER_DSC_PER_MINUTE`), the
  issuing country's (`REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE`; the
  certificate issuer's `C=`) and the network's (`REGISTER_REFUSALS_PER_MINUTE`,
  at most what the 0.1-CPU lease can verify). Every other refusal is decided
  before the verifier runs and spends none of them.
- **Every refusal** except a signer's or country's daily cap also counts
  against its client: `REGISTER_CLIENT_REFUSALS_PER_WINDOW` in
  `REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS`, sliding, the client keyed as an
  IPv4 address or an IPv6 /`REGISTER_CLIENT_REFUSAL_IPV6_PREFIX` (64, one
  subscriber; the request window stays per /48).

A request whose signer, country, network or client budget is spent is
**shed**: it is queued only with a proof of work at the shedding difficulty,
and answered 428 (with `pow.bits`) before the queue without one. Junk naming
one signer sheds that signer's registrants, who can still pay the work, and
no one else; junk from a shared network (CGNAT, a carrier /48) costs everyone
on it a proof of work for a while, never their registration. Setting a
budget to 0 turns it off.

### The reserved lane

`GAS_CHECK_RESERVED_WAITING` of the queue's places are kept for a passport
not granted in 30 days whose DSC commitment is one the chain already holds
registrations from, **with a proof of work** at `POW_RESERVED_BITS`; such a
check takes the slot ahead of ordinary ones. The known set is
x/personhood's `regs_by_dsc` keys, read whole with one store subspace query
over `EARTH_RPC_URL` at start and every `KNOWN_DSC_REFRESH_SECONDS` (a
failed refresh keeps the last set).

The lane also needs `dsc_der` to be that signer: the backend recomputes the
chain's DSC commitment from the certificate (`services/dsccommit`, the port
of `x/pki/certs.DscCommitmentOf`, Brainpool and explicit-parameter curves
included, pinned to the chain for seven certificates) in a worker thread,
one at a time, cached by key, for keys of at most 512 bytes (RSA 4096); a
larger or unparseable key takes the ordinary lane unhashed. A mismatch is
400. At most one priority check per DSC commitment waits or runs at a time;
another request naming that signer meanwhile takes the ordinary lane.
Refusals never demote a signer. A signer's first passport is not in the
set and takes the ordinary lane, which only fills under a flood.

### Proof of work (wallets implement this)

Hashcash over the registration, checked with one SHA-256 (`services/pow`):

    input = "earth-gas-pow/v1:" + ts + ":" + binding + ":" + nullifier + ":" + nonce   (ASCII)
    valid = SHA-256(input) has at least `bits` leading zero bits

- `ts`: unix seconds when the stamp was made; accepted within
  `POW_MAX_AGE_SECONDS` (600) of the server's clock, either way.
- `binding`, `nullifier`: `public_signals[1]` and `public_signals[2]`
  (`PASSPORT_ADDRESS_INDEX`, `PASSPORT_NULLIFIER_INDEX`) exactly as sent. The
  binding covers idc, both pcs and both ciphertexts, so a stamp is good for
  one registration.
- `nonce`: 1..64 characters of `[0-9A-Za-z]`.
- Sent as `"pow": {"ts": 1759363200, "nonce": "1f3a"}`.

`GET /gas/pow` answers

    {"version": "earth-gas-pow/v1", "algorithm": "sha256",
     "input": "earth-gas-pow/v1:<ts>:<public_signals[1]>:<public_signals[2]>:<nonce>",
     "bits", "reserved_bits", "shedding_bits", "shedding", "max_age_seconds"}

`bits` admits a request on every path right now: the reserved lane's, or the
shedding difficulty while the network's budget or the asking client's own is
spent (`shedding: true`). Difficulty is `POW_RESERVED_BITS` (16) or
`POW_SHED_BITS` (20), plus up to `POW_LOAD_EXTRA_BITS` (2) as the gas-check
queue fills, capped at `POW_MAX_BITS` (22). 2^20 hashes is about a second
natively on a phone.

The wallet flow: `GET /gas/pow`, make a stamp at `bits`, post. On 428 read
`pow.bits`, make a new stamp (fresh `ts`) and post again; a 428 also answers
a stamp already used or too far from now. A stamp that is relied on (the
reserved lane or shedding) is used once, and given back when the check it
paid for never ran (503, or 429 for a check already in flight). A stamp
that is not needed is ignored and not consumed.

## Privacy streams

### URL scheme

`genesis` is the first 16 hex digits (lowercase) of the hash of the chain's
first block. A relaunch keeps the chain id, and full pages are cached
`immutable`, so every stream lives under a base that names both:

1. `GET /privacy/status` (`max-age=2`): read `base`, `chain_id`, `genesis`
   (and `genesis_hash`, the full hash). `base` is null until the indexer has
   met its chain.
2. If `(chain_id, genesis)` differs from what the local sync was built from,
   discard the local trees and resync from zero.
3. Fetch every stream under `base` = `/privacy/<chain_id>/<genesis>`. A path
   naming any other chain is 404 `no-store`; on a 404 go back to 1.

### Common rules

- Compact JSON, gzip'd: rows are arrays, their column names in `fields`. 32-byte
  values are lowercase hex, ciphertexts standard base64.
- **Paging.** `limit` is one of `PRIVACY_PAGE_SIZES` (100 or 1000; default
  1000), anything else 400 `no-store`. Position- and index-paged streams
  (`notes`, `identity`, `stake/notes`, `stake/nullifier-tree`, `handles`,
  `debt_rows`) take only a page-aligned cursor: `from_pos` / `from_index` a
  multiple of `limit` (else 400 `no-store`), and page k is exactly positions
  `[k*limit, (k+1)*limit)`. A short page (`complete: false`) reaches the tip;
  its `next_*` is one past the last row, and to continue later ask for the page
  that contains it (`next - next % limit`) and drop the rows already held. For
  the two indexed trees the first page is `from_index=0` and holds leaves
  1..limit-1 (leaf 0, the sentinel, is never a row). Height-paged streams
  (`nullifiers`, `identity/zeroed`, `stake/nullifiers`, `stake/roots`,
  `stake/snapshots`) take any `from_height`; a page never splits a block, so
  `next_height` is always a clean cursor (one block larger than `limit` comes
  whole).
- **Consistency.** Each response's rows and its `synced_height` /
  `next_height` come from one SQLite snapshot.
- **Caching.** A page that filled its limit covers a closed range and is
  `public, max-age=31536000, immutable`, once every height in it has passed
  the indexer's tree-size check; otherwise `max-age=2`. Identity leaves
  (zeroable later) are `max-age=10` when full, `debt_rows` and `handles`
  always `max-age=2`, rates 30 s (86400 for a closed epoch).
- **Halted index.** Every `{base}/*` answer is 503 `no-store`
  (`Retry-After: 60`); `/privacy/status` says why in `halted`.
- **Admission** (`services/privacygate`, before any handler): only the
  canonical spelling of a URL (known parameters, each once, in alphabetical
  order, plain decimals without leading zeros, nothing percent-encoded;
  else 400 `no-store`); an unknown path is 404 `no-store`; at most
  `PRIVACY_MAX_CONCURRENT` responses in flight (503, `Retry-After: 1`);
  `PRIVACY_IP_MAX_PER_WINDOW` requests per client per window (429). Only CDN
  misses reach the origin; the Cloudflare rules are in
  deploy/akash/README.md.
- **CORS.** Every `/privacy` response, refusals included, carries
  `Access-Control-Allow-Origin: PRIVACY_CORS_ORIGIN` whatever the Origin
  (fixed, so a CDN copy is right for everyone); a local dev origin
  (`http://localhost[:port]`, `http://127.0.0.1[:port]`) gets its own back
  with `no-store`. GET and HEAD, no credentials; OPTIONS is 204.
- Integer parameters above 2^63-1 are 422.

### Status

    GET /privacy/status        (also {base}/status)

    {"chain_id", "genesis", "genesis_hash", "base", "synced_height", "synced_time",
     "start_height", "notes", "note_format": 2, "identity_leaves", "nullifiers",
     "stake_notes", "stake_nullifiers", "stake_nf_tree_size", "stake_note_format": 2,
     "debt_tree_size", "handles", "handles_height", "handles_stale", "halted"}

`notes`, `identity_leaves`, `stake_notes` are tree sizes; `stake_nf_tree_size`
and `debt_tree_size` count the sentinel (0 when empty). `halted` is null or
the reason the indexer stopped.

### Notes (format 2)

    GET {base}/notes?from_pos=&limit=

    {"format": 2,
     "fields": ["position", "height", "cm", "ciphertext", "amount", "owner_pk", "rho", "rcm"],
     "synced_height", "from_pos", "next_pos", "complete",
     "notes": [[position, height, cm, ciphertext, amount, owner_pk, rho, rcm], ...]}

| column | value |
|---|---|
| `position` | leaf position in the note tree |
| `height` | block that appended it |
| `cm` | note commitment, hex |
| `ciphertext` | base64; `null` exactly for an open note |
| `amount` | `"<n><denom>"` when the value is public (shield, chain mint, open note), else `null` |
| `owner_pk`, `rho`, `rcm` | an open note's public opening, hex; all three `null` on every other row |

Three kinds of row:

1. **Bundle output** (`amount` null, `ciphertext` set): trial-decrypt.
2. **Shielded or chain-minted note** (`amount` and a 177-byte `ciphertext`
   set): decrypt with `DecryptBlindNote` (no asset or value inside),
   recompute `pc` and check `cm = H(TAG_CM, AssetID(denom), amount, pc)`
   with the row's amount. Undelegation payouts are such rows (`"<n>uerth"`,
   the undelegate msg's ciphertext), minted in a later block's EndBlock.
3. **Open note** (`ciphertext` null, `amount` and the opening set): the
   referral note the chain mints to a referrer handle's address. A wallet
   takes rows whose `owner_pk` is its own, computes
   `pc = H(TAG_PC, owner_pk, rho, rcm)` and checks
   `cm = H(TAG_CM, AssetID(denom), amount, pc)`; the note is then its own,
   spendable with its nk. Matching is local over rows it downloads anyway.

**Split payouts.** A payout above 2^63-1 (an LP leg, up to 128 notes, or an
undelegation) is minted as several consecutive kind-2 rows with the same
ciphertext, each its own position and amount (2^63-1 each, the last the
remainder). Decrypt once and check every row's `cm` with that row's amount:
each is a separate note. Read columns by name and refuse a page whose
`format` is not 2.

### Nullifiers

    GET {base}/nullifiers?from_height=&limit=

    {"fields": ["height", "nullifiers"], "synced_height", "from_height", "next_height",
     "complete", "blocks": [[height, [nf, ...]], ...]}

Every nullifier the pool spent, in spend order within a block.

### Identity

    GET {base}/identity?from_index=&limit=

    {"fields": ["index", "height", "leaf", "zeroed_height", "time"], "synced_height",
     "size", "from_index", "next_index",
     "leaves": [[index, height, leaf, zeroed_height, time], ...]}

    GET {base}/identity/zeroed?from_height=&limit=

    {"fields": ["height", "indexes"], "synced_height", "from_height", "next_height",
     "complete", "blocks": [[height, [index, ...]], ...]}

The identity tree's leaves in index order; `time` is the block time (unix
seconds) of `height`, `zeroed_height` the block that zeroed the leaf (a zeroed
leaf is 0 in the tree) or null. A wallet that holds a range follows
`/identity/zeroed` rather than re-reading leaves.

### Roots and rates

    GET {base}/roots/latest

    {"synced_height", "note": R, "identity": R, "stake": R}
    R = {"root", "tree_size", "height", "time"} or null

    GET {base}/rates?epoch=

    {"fields": ["validator", "rate", "supply", "epoch", "height"], "synced_height",
     "epoch", "latest_epoch", "rates": [[validator, rate, supply, epoch, height], ...]}

Rates are each validator's derth rate at the end of `epoch`, or each
validator's latest without it. An epoch sweeps 200 validators a block; the
rest come in following blocks and are labelled with the epoch the sweep
belongs to.

### Stake notes (format 2)

x/shieldedstaking's stake note tree (owner-locked `derth/<valoper>` notes,
one per validator a wallet stakes with), served like the pool's.

    GET {base}/stake/notes?from_pos=&limit=

    {"format": 2, "fields": ["position", "height", "cm", "ciphertext"],
     "synced_height", "from_pos", "next_pos", "complete",
     "notes": [[position, height, cm, ciphertext], ...]}

| column | value |
|---|---|
| `position` | leaf position in the stake note tree |
| `height` | block that appended it |
| `cm` | `H(TAG_STAKE, AssetID(derth/<valoper>), amount, spc, label)`, label 0 or `H(TAG_SLABEL, move_key, move_time, exposed)` |
| `ciphertext` | base64, never null: the wallet stake ciphertext, exactly 201 bytes, `epk \|\| AEAD(0x04 \|\| asset \|\| amount \|\| rho \|\| rcm \|\| move_key \|\| move_time \|\| exposed) \|\| tag` (label fields zero when unlabelled) |

The chain mints no stake note: every row is a stake proof output (lane A's
`commitment`, then the credit lane's `credit_commitment`), the zero note of
a full exit included. A wallet finds its stake notes by trial decryption
only. Read columns by name and refuse a page whose `format` is not 2.

### Stake nullifiers, the stake nullifier tree, roots and snapshots

    GET {base}/stake/nullifiers?from_height=&limit=      {"fields": ["height", "nullifiers"], ..., "blocks"}
    GET {base}/stake/nullifier-tree?from_index=&limit=   {"fields": ["index", "nullifier", "height"],
                                                          "synced_height", "size", "from_index",
                                                          "next_index", "complete", "nullifiers"}
    GET {base}/stake/roots?from_height=&limit=           {"fields": ["height", "root", "tree_size", "time"], ..., "roots"}
    GET {base}/stake/snapshots?from_height=&limit=       {"fields": ["height", "proposal_id", "root",
                                                          "tree_size", "nf_root", "nf_size"], ..., "snapshots"}

Every non-zero nullifier of a stake proof is inserted, padding ones
included: a first delegation spends a padding nullifier (one nullifier, one
note), a redelegation two (the change and the labelled credit; its
`move_key` is the second). The stake nullifier tree is an indexed (sorted)
depth-32 Poseidon2 tree whose leaf positions are insertion order (leaf 0
the sentinel), so `/stake/nullifier-tree` serves it by leaf index; `size`
counts the sentinel, 0 when empty.

`/stake/roots` is every root the chain recorded (one per block that moved
the tree, the empty tree's at the first block with `tree_size` 0), so a
wallet can pick any anchor still in the window. `/stake/snapshots` is every
proposal snapshot (`root` `""` when the note tree had none yet; `nf_size`
counts the sentinel).

To vote: take the proposal's snapshot, insert leaves `1 .. nf_size - 1` in
index order into an indexed tree (`leaf = H(TAG_SNFL, value, next_value,
next_index)`; `services/zk/indexed.py` is a reference), check the root equals
`nf_root`, and prove the low leaf of the note's nullifier.

### Handles (owner)

    GET {base}/handles?from_index=&limit=

    {"fields": ["handle", "address", "status", "expires_at", "renewal_until", "owner"],
     "synced_height", "height", "time", "size", "stale", "from_index", "next_index",
     "last_page", "handles": [[handle, address, status, expires_at, renewal_until, owner], ...]}

The whole handle directory, so a wallet paying a handle does not tell this
server which: a snapshot of the chain's `Query/Handles` read at one height
(`height`, block time `time`), in handle order, paged by place in it. Read
pages until `last_page`; if `height` changes between pages, start over.

- `status` is the chain's at `time`: `live` resolves (pay it, or name it as
  a registration's `affiliate_handle`); `renewal` (owner-only, until
  `renewal_until`) and `free` do not. Treat a `live` entry whose `expires_at`
  has passed by your clock as not resolving.
- `owner` is the handle-scope nullifier holding the handle, 64 lowercase hex,
  or `""` for a handle never claimed. A wallet knows a handle is its own when
  `owner` equals its own handle-scope nullifier
  (`H(TAG_SN, id_secret, Scope("handle"))`), never because the entry names
  its address. It is already public (the handle events carry it).
- `stale` (`handles_stale` in status) is true once the first handle event
  the snapshot has not caught up with is `HANDLES_STALE_BLOCKS` or more
  blocks old. Do not pay a handle from a stale directory.

The indexer re-reads the directory once caught up: after a block with a
`handle_bound` / `handle_moved` / `handle_released` event, once block time
reaches the snapshot's earliest `expires_at` (live) or `renewal_until`
(renewal), and at least every `HANDLES_MAX_AGE_SECONDS` of block time; at
most every `HANDLES_MIN_REFRESH_BLOCKS` blocks. Each page is checked against
the chain's rules (handle format, strict order, known status, `erthz1`
address, `renewal_until >= expires_at >= 0`, owner shape, at most
`HANDLES_MAX_ENTRIES`), parsed in a worker thread, staged in SQLite and
swapped in whole; a failed or malformed read keeps the previous snapshot.

### Debt rows (the slash debt tree)

One row per slashed private redelegation, keyed by its move key (the
redelegation's credit nullifier), holding what its credited exposure is
still worth. A wallet needs every row, the root and `clear_before` to clear
a label or vote a labelled note against the current `debt_root`.

    GET {base}/debt_rows?from_index=&limit=

    {"format": 1,
     "fields": ["index", "key", "retained", "height", "updated_height"],
     "synced_height",
     "size",                  // leaf count, sentinel included; 0 before the first row
     "root",                  // the debt root at synced_height (the empty root when there is no row)
     "root_height",           // the block that last wrote a row, or null
     "window_seconds",        // the chain's Query/DebtTree at clear_before_height,
     "clear_before",          //   null until the indexer has checked
     "clear_before_height",
     "from_index", "next_index", "complete",
     "rows": [[index, key, retained, height, updated_height], ...]}

`index` is the row's leaf (1, 2, ... in insertion order); `retained` only
falls, and a later slash of the same move rewrites the row in place
(`updated_height`), so no page is immutable. To use it: read every page,
insert the rows in `index` order into an indexed tree
(`leaf = H(TAG_DEBTL, key, next_key, next_index, retained)`, sentinel leaf
`H(TAG_DEBTL, 0, 0, 0, 0)` at index 0; `services/zk/debt.py` is a reference)
and check the root equals `root` (if not, a row changed between pages: read
them all again). A move's witness is its own leaf when its key is listed,
else its low leaf (absent: worth the whole exposure). `clear_before` only
grows, so the one served is always safe to name; the label clears when
`move_time < clear_before`. The chain refuses a `debt_root` that is not the
current one. The chain's own `Query/DebtTree`
(`/earth/shieldedstaking/v1/debt_tree`) answers the same.

## The indexer

`services/privacy/indexer.py` reads `block_results` over CometBFT RPC
(`INDEXER_RPC_URL`) from `INDEXER_START_HEIGHT` (default the node's earliest
block) in batches, and applies each block to SQLite (`INDEX_DB`) in one
transaction with the height it reaches: it resumes exactly where it stopped,
and re-applying a block is a no-op. CometBFT blocks are final, so it only
moves forward. The node must keep block results from the start height on
(`discard_abci_responses = false`, no pruning below it); earth-1's node is a
full-history node.

**Events read.** `shielded_note`, `shielded_nullifier` (every bundle
action, MsgSend's included), `shielded_root`, `shielded_shield` /
`shielded_mint` (public amounts; their ciphertext must equal the note's; a
mint with `owner_pk`/`rho`/`rcm` and no ciphertext is an open note),
`register` (a paid referral must name an open-note mint of the same block
with that amount; nothing stored), `identity_leaf` (append, or zero when the
leaf is all zeros), `identity_root`, `shieldedstaking_epoch_validator`,
`shieldedstaking_epoch`, `shieldedstaking_stake_note` (201-byte ciphertext;
`denom`/`amount`/`spc` refused), `shieldedstaking_stake_nullifier`
(`nullifier`, `index`), `shieldedstaking_stake_root`,
`shieldedstaking_snapshot`, `shieldedstaking_unbond_payout` (its positions
must be this block's x/shieldedstaking uerth mints, distinct, one ciphertext,
summing to `amount`; nothing stored), `shieldedstaking_debt_row` (a new key
at exactly the next leaf, a known key at its own, `retained` never rising),
`shieldedstaking_move_slashed` (must follow its row), `shieldedstaking_slash_debt`
(must name its moves' validators and at most their summed debt),
`shieldedstaking_redelegate` (`move_key` must be a stake nullifier of the
block; `minted` refused; nothing stored), and the handle events (only as a
signal to re-read the directory).

**Not read**, because they change no tree and no rate: dex LP events,
`shielded_unshield` and the other per-msg pool events,
`shieldedstaking_self_bond_compounded`, `shieldedstaking_unbond_payout_failed`
(nothing minted; the chain retries), `shieldedstaking_stake_vote` (vote
nullifiers spend nothing and are in no tree) and the other per-msg staking
events.

**Order.** PreBlock and BeginBlock events, then the txs, then EndBlock (the
SDK's `mode` attribute), which is the order notes are appended in.

**Failed txs are read too; never filter on `code`.** A private tx's notes
and nullifiers are written in the ante. SDK v0.53 commits the ante's writes
before running the msgs and, when a msg fails, still returns the ante's
events (only those) in the failed tx's result; a tx whose ante fails writes
nothing and returns no events. So every event in every tx result is state
that persisted (`bin/sdkcheck` confirms it in the SDK's baseapp harness;
`test_failed_tx_ante_events_are_indexed` guards it).

**It halts rather than diverge**, with the reason in `/privacy/status`
`halted` (clear it by wiping `INDEX_DB`): a note, stake note or stake
nullifier leaf out of sequence; a nullifier spent twice; a debt row out of
leaf order or rising; a snapshot past the indexed trees; a root event whose
size differs from the index; a malformed event; a different chain id or
genesis block hash behind the RPC (checked on every start and after every
RPC error); an RPC tip below the indexed height when the node is not
catching up; a block whose parent is not the block indexed before it
(checked every block); or tree sizes (and the debt root) that differ from
the chain's own `Query/Tree`, `Query/IdentityTree`, `Query/StakeTree`,
`Query/StakeNullifierTree` and `Query/DebtTree` at each batch's last height.
That last check catches history the events cannot show (genesis-imported
notes, a start height past the first private tx); when the node cannot
answer it (state pruned) it is skipped with a WARNING, and pages stay
short-lived until it passes (`verified_height`). Each batch also stores the
chain's debt `window_seconds` / `clear_before`.

**The RPC is trusted for `block_results`.** The next header's
`last_results_hash` would not authenticate them: CometBFT v0.38 hashes only
each tx result's deterministic fields and not `finalize_block_events`, where
mints, roots and rates are. The tree-size check and `bin/verify-trees.py`
bound a lying RPC; point `INDEXER_RPC_URL` at a node you run or trust.

An index file whose tables do not have exactly the current columns (one
written for an earlier format) is refused at open: wipe `INDEX_DB`.

### Verifying the trees

    bin/verify-trees.py --db privacy_index.db [--all-roots] [--no-chain]

Rebuilds the note, identity, stake, stake nullifier and slash debt trees from
the index with Python Poseidon2 (`services/zk`, a port of the chain's
`zk/poseidon2`, `zk/merkle`, `zk/indexed`, `zk/debt` and `zk/privacy`, pinned
to Go vectors) and checks: the latest root of each tree (every recorded root
with `--all-roots`) against the root events; every debt row write's leaf and
the root emitted after it; the stake nullifier tree at every snapshot's
`nf_size` against its `nf_root`; every open note's commitment from its
opening; and, unless `--no-chain`, the rebuilt trees against the chain's own
queries (the debt tree row by row) at the synced height. Exit 0 all match, 1
mismatch, 2 the chain could not be asked.

## Deploy

The service runs on Akash behind a Cloudflare tunnel (`api.erth.network`);
`deploy/akash/deploy.yaml` is the SDL, documented inline, and
`deploy/akash/README.md` has the operational detail (the mnemonic, the
Cloudflare cache and rate-limit rules /privacy needs, the ADX host
requirement, sizing).

1. Tag a release (`vX.Y.Z`); CI (`.github/workflows/docker-build.yml`)
   builds and pushes the image on tags only.
2. `bin/digest.sh <tag>` resolves the tag to the digest to pin (read from
   the registry; CI writes it nowhere).
3. `bin/deploy.sh <tag>` updates the lease in `.env`'s `DSEQ` in place (the
   state volume survives); `--print` shows the SDL without submitting.
   `bin/create.py <tag> --provider <akash1...>` makes a new lease instead (a
   new, empty state volume) and points `DSEQ` at it.

Both submit what `bin/build-sdl.py` builds: `deploy.yaml` with the digest
and the two secrets from `.env` (`GAS_WALLET_MNEMONIC`, `TUNNEL_TOKEN`). It
refuses a provider hostname for `EARTH_NODE_URL`, a globally published app
port while `TRUST_CF_CONNECTING_IP` is on, and cloudflared metrics off
loopback. API errors are printed with secrets redacted.

The state volume holds the replay database (losing it lets each passport of
the last 30 days be paid again and resets the caps) and the privacy index
(rebuilt from the chain; after a chain relaunch, wipe it). `EARTHD_VERSION`
in the Dockerfile must be the release of the chain the service grants on.

## Fixtures

`tests/fixtures/privacy/Test*.json.gz` are real blocks: the chain's own app
scenario tests (real proofs, the launch genesis path) recorded as RPC
`block_results`, with the keepers' note, identity, stake and stake
nullifier tree sizes and roots after each block, the slash debt tree's size,
root and `Query/DebtTree` answer, and the chain's `Query/Handles` answer in
pages of one. The chain's redelegation tests move funds outside blocks, so
the recorder adds its own scenario, `TestRecordRedelegateSlashDebt`
(`bin/chainrec/zz_record_scenarios_test.go`), with its proofs in
`bin/chainrec/proofs`. `zk_vectors.json` comes from the chain's Go zk
packages. Both regenerate from a chain checkout without touching it:

    bin/record-chain-fixtures.sh ../earth-network-chain [ref] [../earth-network-mobile/circuits]
    bin/zk-vectors.sh ../earth-network-chain [ref]

The circuits argument (nargo and bb on PATH) proves the recorder scenario's
missing proofs after a circuit change. `tests/fixtures/dsc` holds the
certificates the DSC commitment is pinned with (`x/pki/certs` test data and
generated DSCs).
