# earth network backend

Two jobs: gas grants that let a new human make their first transaction, and the
privacy indexer that serves the shielded pool's public data to wallets (see
[Privacy indexer](#privacy-indexer)).

## Gas grants: why they exist

A new user has no ERTH. On the shielded chain a registration is an unsigned
private tx that pays its fee from a shielded note, so what they need is a note
— and they cannot make one without ERTH. The backend funds that first note.

Registration mints a shielded ERTH reward that pays every later fee, so this
subsidises exactly one transaction per new human.

The Sybil defence is the passport: a grant needs a registration the chain
itself would accept, and is paid once per passport in any 30 days. `/gas/register`
is the only grant. The device-attestation grants (`/gas/challenge`,
`/gas/ios`, `/gas/android`), `/gas/transparent` and `/gas/human` are gone.

## Endpoints

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml, ciphertext_erth,
                           affiliate_handle?,
                           pc_gas, ciphertext_gas, pow?}
    GET  /gas/pow         the proof of work /gas/register needs now
    GET  /health          hot wallet balance and how many grants are left in it

`/gas/register` takes the MsgRegister the app is about to broadcast
(bytes as standard base64, its fee bundle left out; `earthd gas-check`
ignores the bundle, so it may be absent or empty) and, if the chain would
accept it, shields `DUST_UERTH` from the hot wallet into a note to `pc_gas` (a
`MsgShield` carrying `ciphertext_gas`, which the chain emits for the app's own
trial decryption). Every ciphertext is required and is a note's amount-blind
v2 ciphertext (`zk/privacy.EncryptBlindNote`), exactly 177 bytes:
`ciphertext_anml`/`ciphertext_erth` are MsgRegister's own (the proof's binding
covers them), `ciphertext_gas` is the gas note's.
The app then broadcasts MsgRegister paying its fee from that note. Once per
passport in any 30 days (a sliding window over every id of that passport),
keyed `passport:<nullifier>:<YYYY-MM-DD>`; the replay table stores that key
and nothing else — no address, no pc. Ids from before the window (`:<YYYY-MM>`)
share the passport's prefix and count the same. The check is the
chain's own, through `earthd gas-check registration` (installed in the image
from the chain release; see the Dockerfile). Proofs are verified here, never by
the node.

Answers are `{status, message, tx_hash?}` with 200 (sent), 202 (broadcast,
unresolved), 4xx (cannot succeed as sent; 409 already granted, 413 body over
64 KiB, 428 proof of work needed, 429 rate or daily limit) or 5xx (retry).

### Once per passport in 30 days — a switch included (by design)

Grants are once per passport in a sliding 30-day window (keyed by calendar
month, a grant on the 31st and another on the 1st were two, a day apart),
and gas-check accepts a *switch* (a passport already registered moving to a
new identity) as readily as a first registration. So a holder can draw one
grant every 30 days by switching. That is accepted: it costs `DUST_UERTH` per passport per 30 days at
most, and a switch is a real registration tx the chain charges a fee for (paid
from that very note). Keying the grant on the nullifier alone would strand a
holder whose first gas note was lost.

**Cap pressure (audit-4 B4).** Every registered passport can re-draw a
grant every 30 days by switching, so the registered population is a
standing claim on the daily cap: N holders cycling switches spend N/30
grants a day without a single new human. Under one shared cap that crowded
out first registrations, the grants the service exists for. Switches are
therefore capped apart: gas-check's verdict says `switched`, and a switch
grant counts only against `REGISTER_SWITCH_GRANT_MAX_PER_DAY` (100), a first
registration only against `REGISTER_GRANT_MAX_PER_DAY` (500); the replay
table records each grant's kind (`''` or `switch`, nothing else). The two
together bound the hot wallet's daily spend. The before-check 429 fires only
when both caps are spent (whether a request is a switch is gas-check's
answer), so while only one is spent a request of that kind costs a check and
is then refused 429.

### When the shield's outcome is unknown

The shield tx is signed before it is posted, so its hash is known up front.
A failure while looking up the hot wallet's account or simulating moved
nothing: the passport is released (502, try again). If the post itself fails
in a way the node may already have accepted it (a read timeout, a dropped
connection), the chain is asked for the tx by that hash: landed is a 200,
included-and-failed releases (502), and not seen within the wait is 202
`pending` with the `tx_hash` — the claim is kept, since that tx may still
land, and the app watches the hash. An unresolved send without a hash (none
exists before signing) releases the claim. The backend logs neither the hash
nor the passport for a grant (only "registration gas note sent"): a log line
naming the shield tx at the moment a passport checked out would tie the
public registration to its gas note by timing.

### What runs before gas-check

A proof verification is the expensive part (one at a time, ~120 MB), so
everything that can refuse a request without one runs first, in this order:

0. **Body size**: over `MAX_BODY_BYTES` (64 KiB; the largest real request is
   ~56 KiB) → 413, before anything is read or parsed (`services/bodylimit`,
   streamed bodies cut off as they arrive). Each field also has a loose
   length cap → 422.
1. **Per-client window**: `REGISTER_IP_MAX_PER_WINDOW` requests per
   `REGISTER_IP_WINDOW_SECONDS` (default 10 an hour), junk included → 429.
   A client is an IPv4 address or an IPv6 /`REGISTER_IPV6_PREFIX` (48 by
   default: VPS hosts hand one customer a /48, and keyed by /64 that was
   65536 clients' budgets; 56 or 64 are looser, for an ingress where many
   real users share a /48). Its address is
   `CF-Connecting-IP` when `TRUST_CF_CONNECTING_IP=true` (right only where
   Cloudflare is the sole ingress — the Akash lease is tunnel-only and sets
   it), otherwise the TCP peer (the default). Each client is one fixed-size
   sliding-window counter; at most `REGISTER_IP_MAX_TRACKED` (20000, ~2.5 MiB)
   are kept, least recently seen evicted first.
2. **Shape**, as `MsgRegister.ValidateBasic`: base64, idc/pcs canonical
   32-byte field elements, proof 1..32 KiB, dsc_der 1..8 KiB, all three
   ciphertexts exactly 177 bytes (a missing one is 422), 1..16 public signals that are canonical decimals; a
   referral is `affiliate_handle` alone (a handle: a-z, 0-9, -, 3..32, no leading or trailing dash) → 400.
   `affiliate_pc` / `affiliate_ciphertext` (MsgRegister 11 and 12, removed in chain audit round 5: the
   chain mints the referral note itself) in the body, even empty, → 400 naming them.
3. **Binding**: `public_signals[address_index]` must equal
   `RegistrationBinding = H(TAG_REG, idc, pc_anml, Bytes(ciphertext_anml),
   pc_erth, Bytes(ciphertext_erth), affiliate)`, affiliate 0 or
   `H(TAG_AFFILIATE, Bytes(affiliate_handle))` (Python Poseidon2, pinned to
   the chain's Go vectors) → 400. Someone else's proof with notes or
   ciphertexts of one's own stops here.
4. **Date**: `public_signals[current_date_index]` (YYMMDD) within
   `current_date_max_skew_seconds` of now (+10 min) → 400.
5. **Replay**: any `passport:<public_signals[nullifier_index] as 32-byte hex>:…`
   claimed in the last 30 days → 409.
6. **Daily cap**: `REGISTER_GRANT_MAX_PER_DAY` first-registration grants
   and `REGISTER_SWITCH_GRANT_MAX_PER_DAY` switch grants in the last 24 h,
   counted apart (see "Cap pressure" above) → 429; refused here only when
   both are spent, otherwise after gas-check names the kind.
7. **Refusal budgets and proof of work**: junk with a forged binding passes
   every check above, and only gas-check refuses it. Only a refusal that
   cost a proof verification (the chain's `invalid registration proof`)
   spends a budget: everything else gas-check refuses on — the DSC does not
   chain, a signer or country at its daily cap, a used binding — is decided
   before the verifier runs, and a real registrant meeting a cap must not
   shed anyone. Those refusals are counted per minute against three
   budgets: the DSC commitment's (`REGISTER_REFUSALS_PER_DSC_PER_MINUTE`, 3),
   the issuing country's (`REGISTER_REFUSALS_PER_COUNTRY_PER_MINUTE`, 4;
   the DSC certificate's issuer `C=`, which for a DSC that chains is the
   CSCA's country the chain caps by) and the network's
   (`REGISTER_REFUSALS_PER_MINUTE`, 5: at most what the 0.1-CPU lease can
   verify, about six a minute, so verified junk trips it). A request whose signer,
   country or the network has spent its budget is *shed*: it is queued only
   with a proof of work at the shedding difficulty, and answered **428**
   (with `pow.bits`) before the queue without one. Junk naming one signer
   sheds that signer's registrants — who can still pay the work — and no
   one else. Every refusal, cheap ones included and in either lane, also
   counts against the client that sent it
   (`REGISTER_CLIENT_REFUSALS_PER_WINDOW`, 3 in
   `REGISTER_CLIENT_REFUSAL_WINDOW_SECONDS`, 3600, sliding): past it the
   client is answered **429** before the queue until they age out
   (audit-5 M3).
8. **One check per client**: a client with a gas-check already queued or
   running gets 429 at once rather than a second place in the queue; the queue
   as a whole is bounded by `GAS_CHECK_MAX_WAITING` (503).

**The reserved lane.** `GAS_CHECK_RESERVED_WAITING` (5) of the queue's places
are kept for a passport not yet granted in 30 days whose DSC commitment
(`public_signals[PASSPORT_DSC_KEY_INDEX]`, 3) is one the chain already holds
registrations from, **with a proof of work** at `POW_RESERVED_BITS`, and
such a check takes the slot ahead of ordinary ones. Without the work the
same request takes the ordinary lane. The known-DSC set is x/personhood's
`regs_by_dsc` keys, read whole with one store subspace query
(`/store/personhood/subspace` over `EARTH_RPC_URL`) at startup and every
`KNOWN_DSC_REFRESH_SECONDS` (600); a failed refresh keeps the last set. The
request's `dsc_der` must also be that signer: the backend recomputes the
chain's DSC commitment from the certificate (`services/dsccommit`, the
port of `x/pki/certs.DscCommitmentOf`, Brainpool and explicit-parameter
curves included, pinned to the chain's output) and a mismatch is refused
400 before the queue, since the chain refuses it for certain (audit-4 B1,
audit-5 M1). The hash runs in a worker thread, one at a time, cached by
key, and only over a key of at most 512 bytes (RSA 4096, the largest real
DSC): a larger key, which the chain accepts up to 2048 bytes, takes the
ordinary lane unhashed. Both the commitment and the certificate are
public (every registration publishes them), so junk can still copy a real
pair, at a proof of work a request. So at most **one** priority check per
DSC commitment waits or runs at a time; a second request naming that
signer meanwhile takes the ordinary lane. No refusal demotes a signer
(audit-5 M3: audit 4's cooldown, five refusals naming a DSC in an hour,
was anyone's to trigger with the signer's public certificate, and evicted
its real registrants from the lane). Junk naming one signer holds one place,
only while its check runs, and its clients lose their places to the client
refusal budget. A signer's first passport is not in
the set and takes the ordinary lane, which only fills under a flood.

### Proof of work (wallets implement this)

Hashcash over the registration, checked here with one SHA-256
(`services/pow`):

    input  = "earth-gas-pow/v1:" + ts + ":" + binding + ":" + nullifier + ":" + nonce   (ASCII)
    valid  = SHA-256(input) has at least `bits` leading zero bits

- `ts`: unix seconds when the stamp was made; accepted within
  `POW_MAX_AGE_SECONDS` (600) of the server's clock, either way.
- `binding`, `nullifier`: `public_signals[1]` and `public_signals[2]`
  (`PASSPORT_ADDRESS_INDEX`, `PASSPORT_NULLIFIER_INDEX`) exactly as the
  request sends them, decimal strings. The binding covers idc, both pcs and
  both note ciphertexts, so a stamp is good for that one registration.
- `nonce`: 1–64 characters of `[0-9A-Za-z]` (a hex counter is fine).
- Sent in the body: `"pow": {"ts": 1759363200, "nonce": "1f3a"}`.

`GET /gas/pow` answers `{version, algorithm, input, bits, reserved_bits,
shedding_bits, shedding, max_age_seconds}`; `bits` admits a request on every
path right now. Difficulty is adaptive: `POW_RESERVED_BITS` (16) for the
reserved lane, `POW_SHED_BITS` (20) while shedding, plus up to
`POW_LOAD_EXTRA_BITS` (2) as the gas-check queue fills, capped at
`POW_MAX_BITS` (22). 2^20 hashes is about a second natively on a phone, a
few seconds in a browser. The wallet flow:

1. `GET /gas/pow`, make a stamp at `bits`, `POST /gas/register` with it.
2. On **428**, read `pow.bits` from the answer, make a new stamp (fresh
   `ts`) at that difficulty and post again. A 428 also answers a stamp that
   was already used, or whose `ts` is too far from now.
3. A stamp that is relied on (reserved lane or shedding) is accepted
   once; a request answered 503, or 429 for a check already in flight,
   gives its stamp back. Retry a 403 (a refusal) with a new one.

A stamp that is not needed (ordinary lane, nothing shed) is ignored and not
consumed. Under the shared ingress (`TRUST_CF_CONNECTING_IP`) the per-client
limits still apply to every request, worked or not.

### The gas note can be claimed from the mempool (accepted)

A MsgRegister in the mempool carries everything `/gas/register` asks for
except `pc_gas`/`ciphertext_gas`, which are the requester's own. Someone who
copies it from the mempool before the registrant has drawn a grant gets the
passport's grant (a `DUST_UERTH` note) paid to a pc of theirs, and the
registrant's own request is then 409 for 30 days. That only happens when a
registrant broadcasts before asking for gas — the app asks first, since it
pays MsgRegister's fee from that very note — so the copier takes one dust
note from a registration that did not need it; the registration itself is
unaffected (the proof binds idc and the reward notes, not pc_gas), and the
rolling daily cap bounds the total. Binding pc_gas into the request would
need a signature by a key the registrant does not have before registering
(the idc is a commitment, not a key), so this is documented as an accepted
low risk rather than closed.

The indexes are personhood params, mirrored in config:
`PASSPORT_NULLIFIER_INDEX=2`, `PASSPORT_ADDRESS_INDEX=1`,
`PASSPORT_CURRENT_DATE_INDEX=0`, `PASSPORT_DSC_KEY_INDEX=3`,
`PASSPORT_DATE_MAX_SKEW_SECONDS=172800` (earth-1 genesis `nullifier_index`,
`address_index`, `current_date_index`, `dsc_key_index`,
`current_date_max_skew_seconds`). If gas-check returns a nullifier other than
ours the request is 503 and nothing is claimed: the index is misconfigured.
Whether the DSC is a trusted signer is not checked here (it needs the
chain's PKI state); gas-check does that before verifying the proof. The
known-DSC set only picks the queue lane.

## Running

    pip install -r requirements.txt
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC, or GAS_ENABLED=false
    uvicorn main:app --host 0.0.0.0 --port 8000

Tests need no chain: gas-check's verdict is stood in for, and recorded chain
blocks are replayed for the indexer.

    pip install -r requirements-dev.txt
    python -m pytest

## Watch the wallet

`/health` reports `grants_remaining`. When the hot wallet runs dry every grant
fails after the registration checks out. Alert on it. The balance is read
in the background every `HEALTH_REFRESH_SECONDS` (30) and served from
memory with `Cache-Control: public, max-age=30` (`read_at` says when), so a
request never reaches the LCD (audit-5 L3); `"status": "degraded"` means
the last read failed.

## Privacy indexer

Wallets on the shielded chain never ask anyone about their own notes. They
download every note commitment and ciphertext, every nullifier and every
identity leaf, rebuild both trees locally and trial-decrypt. This serves that
data, and nothing narrower: there is no endpoint keyed by anything a wallet
derives from its keys.

    GET /privacy/status          chain_id, genesis, base, synced height, counts, halted reason

and under `base` = `/privacy/<chain_id>/<genesis>`:

    GET {base}/status
    GET {base}/notes?from_pos=&limit=               [position, height, cm, ciphertext, amount]
    GET {base}/nullifiers?from_height=&limit=       [[height, [nf, ...]], ...]
    GET {base}/identity?from_index=&limit=          [index, height, leaf, zeroed_height, time]
    GET {base}/identity/zeroed?from_height=&limit=  [[height, [index, ...]], ...]
    GET {base}/roots/latest                         note, identity and stake roots, size, height, time
    GET {base}/rates?epoch=                         [validator, rate, supply, epoch, height]
    GET {base}/stake/notes?from_pos=&limit=         [position, height, cm, ciphertext, denom, amount, spc]
    GET {base}/stake/nullifiers?from_height=&limit= [[height, [nf, ...]], ...]
    GET {base}/stake/nullifier-tree?from_index=&limit=  [index, nullifier, height]
    GET {base}/stake/roots?from_height=&limit=      [height, root, tree_size, time]
    GET {base}/stake/snapshots?from_height=&limit=  [height, proposal_id, root, tree_size, nf_root, nf_size]
    GET {base}/handles?from_index=&limit=           [handle, address, status, expires_at, renewal_until]

### URL scheme for wallets

`genesis` is the first 16 hex digits (lowercase) of the hash of the chain's
first block; `/privacy/status` also gives the full `genesis_hash`. earth-1
has been relaunched under the same chain id, and full pages are served
`immutable`, so a CDN could otherwise hand a wallet the previous chain's
notes after a relaunch. Keyed paths make that impossible:

1. `GET /privacy/status` (unkeyed, `max-age=2`). Read `base`, `chain_id`
   and `genesis`. `base` is null until the indexer has met its chain.
2. If `(chain_id, genesis)` differs from what the wallet's local sync was
   built from, discard the local trees and resync from zero.
3. Fetch every stream under `base`. A path naming any other chain is
   `404` with `Cache-Control: no-store`; on a 404, go back to 1.

A wallet that wants to pin the chain independently can compare
`genesis_hash` with its own node's hash for the chain's first block.
The old unkeyed stream paths (`/privacy/notes`, ...) are gone.

Compact JSON (rows as arrays, field order in `fields`), gzip'd.

**Paging rule (wallets implement this; audit-4 B3).** `limit` is one of
`PRIVACY_PAGE_SIZES` — 100 or 1000; default 1000; anything else is 400. A
position- or index-paged stream (`notes`, `identity`, `stake/notes`,
`stake/nullifier-tree`) takes only a page-aligned cursor: `from_pos` /
`from_index` must be a multiple of `limit` (else 400, `no-store`), and page
`k` is exactly positions `[k*limit, (k+1)*limit)`. A full page's
`next_pos`/`next_index` is the next aligned cursor. A page that reaches the
tip is short (`complete: false`) and its `next_*` is one past the last row;
to continue later, ask for the page that contains it,
`from = next - next % limit`, and drop the rows already held. The stake
nullifier tree's first page is `from_index=0` (leaf 0, the sentinel, is never
a row, so it holds leaves 1..limit-1). Every wallet thus asks for the same
URLs, a CDN keeps one copy of each, and an uncached page is no longer a URL
anyone can mint (every distinct `from_pos` used to be a distinct cache key,
and a 5000-row page cost ~8 MiB of heap and ~0.3 s on a laptop, seconds on
the lease; a 1000-row page is ~1.6 MiB). Height-paged streams keep a free
`from_height` (a page ends at a block boundary, so `next_height` cannot be
aligned); their rows are 32-byte values and the fixed sizes apply. All of
/privacy is behind an in-flight cap (`PRIVACY_MAX_CONCURRENT`, 4: 503 with
`Retry-After: 1`) and a per-client rate (`PRIVACY_IP_MAX_PER_WINDOW`, 240 per
`PRIVACY_IP_WINDOW_SECONDS`, 60: 429), counting only what misses the CDN; the
Cloudflare cache and rate-limit rules are in deploy/akash/README.md.

Height-paged streams never
split a block, so `next_height` is always a clean cursor; a response's rows
and its `synced_height`/`next_height` are read in one SQLite snapshot, so a
block committed mid-request is never skipped by following `next_height`.
Integer parameters are bounded to int64 (larger: 422). A page that filled
its limit covers a closed range and is served `immutable`; the tip page,
identity leaves (zeroable later), roots, rates and status get short max-ages.
`amount` is set only for notes whose value is already public (a shield or a
module mint). Every note row has a `ciphertext`; a shielded or minted note's
is the required 177-byte amount-blind v2 ciphertext (`EncryptBlindNote`: no
asset or value inside — the wallet decrypts it, recomputes `pc` and checks
`cm = H(TAG_CM, AssetID(denom), amount, pc)` against the row's `amount`). A wallet that has synced identity leaves follows
`/identity/zeroed` rather than re-reading them. An identity row's `time` is
the block time (unix seconds) of its `height`.

`/stake/*` is x/shieldedstaking's stake note tree (owner-locked
`derth/<valoper>` and `unbond/<valoper>/<epoch>` notes; its own nullifiers
and roots), served the same way. Every stake note row has a `ciphertext`. A
stake note the chain minted (delegation, undelegation claim, vote re-mint,
unlocked position) also has public `denom`, `amount` and stake pc `spc`, and
its `ciphertext` is the blind stake ciphertext (177 bytes, salt
`earth.stake.v1`, version `0x03`; `EncryptBlindStakeNote`); one a stake proof
created has the proof's `ciphertext` and nulls for the rest.

### Stream row changes for wallets (chain fced976)

One note-discovery rule: a wallet finds every note it owns by trial
decryption alone.

- `/notes`: unchanged columns. Minted and shielded rows (`amount` set) now
  always carry a 177-byte v2 ciphertext; before, it could be empty. Decrypt
  with `DecryptBlindNote`, then match `cm` using the row's public `amount`.
- `/stake/notes`: unchanged columns. Minted rows (`denom`/`amount`/`spc`
  set) now carry a `ciphertext` (was `null`): the blind stake ciphertext.
  Decrypt, recompute `spc = H(TAG_SPC, owner_pk, rho, rcm)`, compare with the
  row's `spc`. Created rows are as before.
- Nullifier, identity, root and rate streams are unchanged. MsgSend and the
  private fee emit the same events as before.
- An index built before this format has null stake ciphertexts; the chain
  change is consensus-breaking, so a fresh index (new `INDEX_DB`) goes with
  the new chain. `/stake/roots` is every
root the chain recorded (one per block that moved the tree), so a wallet can
pick any anchor still in the window or a proposal's snapshot root.

### Stake nullifier tree (stake votes, chain ORCHARD_DESIGN.md section 15)

Stake votes no longer spend the note. A vote proves the note's spend
nullifier was absent at the proposal's snapshot, by non-membership in the
stake nullifier tree: an indexed (sorted) depth-32 Poseidon2 tree whose leaf
positions are insertion order (leaf 0 the sentinel, the first nullifier leaf
1). A wallet must rebuild it in exactly the chain's order, so the backend
serves it by leaf index:

    GET {base}/stake/nullifier-tree?from_index=0&limit=1000

    {"fields": ["index", "nullifier", "height"],
     "synced_height": H, "size": S,           // leaf count, sentinel included; 0 when empty
     "from_index": 0, "next_index": N, "complete": true|false,
     "nullifiers": [[1, "<hex32>", 9], [2, "<hex32>", 16], ...]}

`from_index` defaults to 0 and, like every index cursor, must be a multiple
of `limit` (the first page holds leaves 1..limit-1; no row has index 0).
Follow `next_index` while `complete` is true; full pages are `immutable`. Rows are
gap-free and every nullifier appears once: the indexer halts on an `index`
attribute that is not exactly the next one or a repeated nullifier. Failed
txs' nullifiers are included (a claim spends in the private ante, so its
nullifier persists when the tx fails).

To vote on a proposal: read its snapshot (chain `Query/Snapshot`, or
`/stake/snapshots`: `root`, `tree_size`, `nf_root`, `nf_size`); take leaves
`1 .. nf_size - 1` (none when `nf_size` is 0), insert them in index order
into an indexed tree (`leaf = H(TAG_SNFL, value, next_value, next_index)`,
`TAG_SNFL = "earth.snfl"`; `services/zk/indexed.py` is a reference), check
the root equals `nf_root`, and prove the low leaf of your note's nullifier.
`/stake/snapshots` is every snapshot the chain emitted (empty `root` when
the stake note tree had none yet). `/stake/nullifiers` (by height) is
unchanged and lists the same values, in leaf order within a height.
`/status` adds `stake_nf_tree_size`. Vote events' `vote_nullifier` is not
indexed (a wallet remembers its own votes).

An index built before this chain change has no leaf indexes: the API and the
indexer refuse to open it; wipe `INDEX_DB` (the chain change is
consensus-breaking, so the new index goes with the new chain).

### Handle directory (chain 4a663d5)

A handle (`a-z`, `0-9`, `-`; 3..32; no leading or trailing dash) names a
registered human's shielded address (`erthz1...`). Paying a handle is
wallet-side: look it up, pay its address privately. A lookup of one handle
on a server would say who is paying whom, so there is no per-handle
endpoint: `{base}/handles` is the whole directory, like every other stream.

    GET {base}/handles?from_index=0&limit=1000
    -> {fields, synced_height, height, time, size, from_index, next_index, last_page,
        handles: [[handle, address, status, expires_at, renewal_until], ...]}

It is a snapshot of the chain's `Query/Handles` (`/earth/personhood/v1/handles`)
read whole at one height (`height`, block time `time`), in handle order, and
paged by place in it under the usual rule (limit 100 or 1000, `from_index` a
multiple of limit). Read pages until `last_page`; if `height` changes between
pages, start over (the snapshot was replaced). `status` is the chain's at
`time`: `live` resolves (pay it, or name it as a registration's
`affiliate_handle`), `renewal` (owner-only renewal period, until
`renewal_until`) and `free` do not; also treat a `live` entry whose
`expires_at` has passed by your clock as not resolving. Served with
`max-age=2`.

The indexer re-reads it (every page at the last applied height) once caught
up: after a block with a `handle_bound` / `handle_moved` / `handle_released`
event, once block time reaches the snapshot's earliest `expires_at` (live) or
`renewal_until` (renewal), and at least every `HANDLES_MAX_AGE_SECONDS`
(3600) of block time. Each answer is checked against the chain's rules
(handle format, strict order across pages, `next` = the page's last handle,
known status, `erthz1` address, `renewal_until >= expires_at >= 0`, at most
`HANDLES_MAX_ENTRIES`, 200,000); a failed or malformed read keeps the
previous snapshot and the trees go on. A re-read is at most every
`HANDLES_MIN_REFRESH_BLOCKS` (10) blocks, since anyone can put a handle
event in every block; its pages are parsed in a worker thread and staged
in SQLite one at a time, then swapped in whole (audit-5 L4). `/status` adds
`handles`, `handles_height` and `handles_stale`; the stream's `stale` is
the same flag: true once the snapshot is `HANDLES_STALE_BLOCKS` (30) or more
behind a handle event the index applied (audit-5 L5). Do not pay a handle
from a stale directory: it may name another address by now.

### How it follows the chain

`services/privacy/indexer.py` reads `block_results` over CometBFT RPC from
`INDEXER_START_HEIGHT` (default: the node's earliest block), in batches, and
applies each block to SQLite (`INDEX_DB`) in one transaction with the height
it reaches — so it resumes exactly where it stopped and re-applying a block is
a no-op. CometBFT blocks are final, so it only moves forward. Run it inside
the API process (`INDEXER_ENABLED=true`) or alone:

    python -m services.privacy.indexer

Events it reads (privacy/orchard): `shielded_note`, `shielded_nullifier`
(every bundle action, MsgSend's included), `shielded_root`,
`shielded_shield`/`shielded_mint` (public amounts; their `ciphertext` must
equal the note's), `identity_leaf` (append,
or zero when the leaf is all zeros), `identity_root`,
`shieldedstaking_epoch_validator`, `shieldedstaking_epoch`, and the stake
tree's `shieldedstaking_stake_note` (`position_id`, `commitment`,
`ciphertext`, and `denom`/`amount`/`spc` when minted), `shieldedstaking_stake_nullifier`
(`nullifier`, `index`: its leaf in the stake nullifier tree),
`shieldedstaking_stake_root` and `shieldedstaking_snapshot` (`proposal_id`,
`root`, `tree_size`, `nf_root`, `nf_size`). Most stake notes and nullifiers
are written by the msg, so a failed staking msg leaves none; a claim runs in
the private ante, so a failed claim tx's nullifier and change note persist
(and are read, like every failed tx's events). Ignored: dex LP
events (private LP shares are ordinary notes), `shielded_unshield`,
`shieldedstaking_self_bond_compounded` and the other per-msg staking events. Block events are ordered PreBlock/BeginBlock, txs,
EndBlock (the SDK's `mode` attribute), which is the order notes are appended.

**Failed txs are read too — never filter on `code`.** A private tx's notes and nullifiers are written in
the ante. SDK v0.53 commits the ante's writes before running the msgs and,
when a msg fails, still returns the ante's events (only those) in the failed
tx's result; a tx whose ante fails writes nothing and returns no events. So
every event in every tx result is state that persisted, whatever the code.
(`bin/sdkcheck`, run in the SDK v0.53.6 baseapp test harness, confirms it.)
Skipping `code != 0` results would drop notes the chain appended and put
every later position and root out of step; `test_failed_tx_ante_events_are_indexed`
and `test_failed_tx_with_only_failure_code_still_counts_every_event` guard it.

It refuses, and halts until an operator steps in, rather than serve trees that
cannot match the chain: a note position out of sequence, a nullifier twice,
a stake nullifier whose leaf `index` is not exactly the next one, a proposal
snapshot naming a tree size past the index, a
root event whose size differs from the index, a different chain id or block
hash behind the RPC than the one indexed (the chain's first-block hash is
recorded once, and is the `genesis` in the URLs; on every prepare — every
start, and again after any RPC error — the block at the genesis height must
still have it, and the last indexed block's hash must match), an RPC whose
tip is below the indexed height and which is not catching up (a relaunch
under the same chain id restarts low; before, that was retried forever with
`halted` null), a block whose parent (`header.last_block_id`)
is not the block indexed before it (checked on every block, so an RPC
swapped mid-run halts at the first block of the other chain), or tree sizes that differ from the
chain's own (`Query/Tree`, `Query/IdentityTree`, `Query/StakeTree`,
`Query/StakeNullifierTree` at each batch's last height —
this is what catches notes imported at genesis, which emit no events, or a
start height past the first private tx; when the node cannot answer that
query — state pruned at old heights — the skip is logged at WARNING). The
reason is in `/privacy/status` `halted`; clear it by wiping `INDEX_DB`.

**The RPC is trusted for `block_results`.** The next header's
`last_results_hash` would not authenticate them: CometBFT v0.38 hashes only
each tx result's deterministic fields (code, data, gas), no events, and not
`finalize_block_events` at all — which is where mints, roots and rates are.
The tree-size check and `bin/verify-trees.py` (below) bound a lying RPC;
point `INDEXER_RPC_URL` at a node you run or trust.

**Rates past 200 validators.** x/shieldedstaking sweeps 200 validator books
a block (`EpochValidatorLimit`); with more, an epoch's later validators come
in following blocks without an epoch event. They are stored under the epoch
the sweep belongs to (the last `shieldedstaking_epoch` seen), so
`/rates?epoch=` lists every validator.

The node behind `INDEXER_RPC_URL` (CometBFT RPC, default
`https://rpc.erth.network:443`) must keep block results from the start height
on: `storage.discard_abci_responses = false` (the default) and no block
pruning below it. earth-1 runs one node, the validator, and it is a
full-history node (`pruning = "nothing"`, never state synced), so
rpc.erth.network serves every height from 1.

### Verifying the trees

    bin/verify-trees.py --db privacy_index.db [--all-roots] [--no-chain]

rebuilds the note, identity, stake and stake nullifier trees from the index
with Python Poseidon2 (`services/zk`, a port of the chain's `zk/poseidon2`,
`zk/merkle`, `zk/indexed` and `zk/privacy`), checks every chain-minted stake
note's commitment against its public denom, amount and spc, checks the latest
root of each (every recorded root with `--all-roots`) against the root
events the chain emitted, checks the stake nullifier tree's root at every
proposal snapshot's `nf_size` against its `nf_root` (the chain emits no
per-block nullifier root), and compares the rebuilt trees with the chain's
own (including `Query/StakeNullifierTree` size and root) at the synced height. Exit 0 all match, 1 mismatch, 2 the chain could not be
asked.

### Fixtures

`tests/fixtures/privacy/Test*.json.gz` are real blocks: the chain's own app
scenario tests (real proofs, the launch genesis path) recorded as RPC
`block_results` with the keepers' note, identity and stake tree sizes and
roots after each block, the stake nullifier tree's, and the chain's
`Query/Handles` answer at each block in pages of one (personhood, shielded
pool, staking lifecycle, owner-locked stake notes, self-bond compounding,
private dex LP, stake votes on concurrent proposals).
`zk_vectors.json` comes from the chain's Go zk packages. Both regenerate from
a chain checkout without touching it:

    bin/record-chain-fixtures.sh ../earth-network-chain
    bin/zk-vectors.sh ../earth-network-chain
