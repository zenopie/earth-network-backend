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
itself would accept, and is paid once per passport per month. `/gas/register`
is the only grant. The device-attestation grants (`/gas/challenge`,
`/gas/ios`, `/gas/android`), `/gas/transparent` and `/gas/human` are gone.

## Endpoints

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml, ciphertext_erth,
                           affiliate?, pc_gas, ciphertext_gas}
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
passport per month, keyed `passport:<nullifier>:<YYYY-MM>`; the replay table
stores that key and nothing else — no address, no pc. The check is the
chain's own, through `earthd gas-check registration` (installed in the image
from the chain release; see the Dockerfile). Proofs are verified here, never by
the node.

Answers are `{status, message, tx_hash?}` with 200 (sent), 202 (broadcast,
unresolved), 4xx (cannot succeed as sent; 409 already granted, 429 rate or
daily limit) or 5xx (retry).

### What runs before gas-check

A proof verification is the expensive part (one at a time, ~120 MB), so
everything that can refuse a request without one runs first, in this order:

1. **Per-client window**: `REGISTER_IP_MAX_PER_WINDOW` requests per
   `REGISTER_IP_WINDOW_SECONDS` (default 10 an hour), junk included → 429.
   The client is `CF-Connecting-IP` when `TRUST_CF_CONNECTING_IP=true` (the
   default, right only where Cloudflare is the sole ingress — the Akash lease
   is tunnel-only), otherwise the TCP peer.
2. **Shape**, as `MsgRegister.ValidateBasic`: base64, idc/pcs canonical
   32-byte field elements, proof 1..32 KiB, dsc_der 1..8 KiB, all three
   ciphertexts exactly 177 bytes (a missing one is 422), 1..16 public signals that are canonical decimals, affiliate
   an earth address → 400.
3. **Binding**: `public_signals[address_index]` must equal
   `RegistrationBinding = H(TAG_REG, idc, pc_anml, Bytes(ciphertext_anml),
   pc_erth, Bytes(ciphertext_erth), affiliate)` (Python Poseidon2, pinned to
   the chain's Go vectors) → 400. Someone else's proof with notes or
   ciphertexts of one's own stops here.
4. **Date**: `public_signals[current_date_index]` (YYMMDD) within
   `current_date_max_skew_seconds` of now (+10 min) → 400.
5. **Replay**: `passport:<public_signals[nullifier_index] as 32-byte hex>:<YYYY-MM>`
   already claimed → 409.
6. **Daily cap**: `REGISTER_GRANT_MAX_PER_DAY` passport grants in the last
   24 h → 429.
7. **One check per client**: a client with a gas-check already queued or
   running gets 429 at once rather than a second place in the queue; the queue
   as a whole is bounded by `GAS_CHECK_MAX_WAITING` (503).

The indexes are personhood params, mirrored in config:
`PASSPORT_NULLIFIER_INDEX=2`, `PASSPORT_ADDRESS_INDEX=1`,
`PASSPORT_CURRENT_DATE_INDEX=0`, `PASSPORT_DATE_MAX_SKEW_SECONDS=172800`
(earth-1 genesis `nullifier_index`, `address_index`, `current_date_index`,
`current_date_max_skew_seconds`). If gas-check returns a nullifier other than
ours the request is 503 and nothing is claimed: the index is misconfigured.
Whether the DSC is a known, trusted signer is not checked here (it needs the
chain's PKI state); gas-check does that before verifying the proof.

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
fails after the registration checks out. Alert on it.

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
    GET {base}/identity?from_index=&limit=          [index, height, leaf, zeroed_height]
    GET {base}/identity/zeroed?from_height=&limit=  [[height, [index, ...]], ...]
    GET {base}/roots/latest                         note, identity and stake roots, size, height, time
    GET {base}/rates?epoch=                         [validator, rate, supply, epoch, height]
    GET {base}/stake/notes?from_pos=&limit=         [position, height, cm, ciphertext, denom, amount, spc]
    GET {base}/stake/nullifiers?from_height=&limit= [[height, [nf, ...]], ...]
    GET {base}/stake/roots?from_height=&limit=      [height, root, tree_size, time]

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

Compact JSON (rows as arrays, field order in `fields`), gzip'd. Pages default
to 1000 rows and cap at `PRIVACY_PAGE_MAX` (5000). Height-paged streams never
split a block, so `next_height` is always a clean cursor. A page that filled
its limit covers a closed range and is served `immutable`; the tip page,
identity leaves (zeroable later), roots, rates and status get short max-ages.
`amount` is set only for notes whose value is already public (a shield or a
module mint). A wallet that has synced identity leaves follows
`/identity/zeroed` rather than re-reading them.

`/stake/*` is x/shieldedstaking's stake note tree (owner-locked
`derth/<valoper>` and `unbond/<valoper>/<epoch>` notes; its own nullifiers
and roots), served the same way. A stake note the chain minted (delegation,
undelegation claim, vote re-mint, unlocked position) has public `denom`,
`amount` and stake pc `spc` and a null `ciphertext`; one a stake proof
created has a `ciphertext` and nulls for the rest. `/stake/roots` is every
root the chain recorded (one per block that moved the tree), so a wallet can
pick any anchor still in the window or a proposal's snapshot root.

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
`shielded_shield`/`shielded_mint` (public amounts), `identity_leaf` (append,
or zero when the leaf is all zeros), `identity_root`,
`shieldedstaking_epoch_validator`, `shieldedstaking_epoch`, and the stake
tree's `shieldedstaking_stake_note` (`position_id`, `commitment`, then
`denom`/`amount`/`spc` or `ciphertext`), `shieldedstaking_stake_nullifier`
and `shieldedstaking_stake_root`. Stake notes and nullifiers are written by
the msg, not the ante, so a failed staking msg leaves none. Ignored: dex LP
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
cannot match the chain: a note position out of sequence, a nullifier twice, a
root event whose size differs from the index, a different chain id or block
hash behind the RPC than the one indexed (the chain's first-block hash is
recorded once, and is the `genesis` in the URLs), or tree sizes that differ from the
chain's own (`Query/Tree`, `Query/IdentityTree`, `Query/StakeTree` at each batch's last height —
this is what catches notes imported at genesis, which emit no events, or a
start height past the first private tx). The reason is in `/privacy/status`;
clear it by wiping `INDEX_DB`.

The node behind `INDEXER_RPC_URL` (CometBFT RPC, default
`https://rpc.erth.network:443`) must keep block results from the start height
on: `storage.discard_abci_responses = false` (the default) and no block
pruning below it. earth-1 runs one node, the validator, and it is a
full-history node (`pruning = "nothing"`, never state synced), so
rpc.erth.network serves every height from 1.

### Verifying the trees

    bin/verify-trees.py --db privacy_index.db [--all-roots] [--no-chain]

rebuilds the note, identity and stake trees from the index with Python
Poseidon2 (`services/zk`, a port of the chain's `zk/poseidon2`, `zk/merkle`
and `zk/privacy`), checks every chain-minted stake note's commitment against
its public denom, amount and spc, checks the latest root of each (every recorded root with `--all-roots`) against the root
events the chain emitted, and compares the rebuilt trees with the chain's own
at the synced height. Exit 0 all match, 1 mismatch, 2 the chain could not be
asked.

### Fixtures

`tests/fixtures/privacy/Test*.json.gz` are real blocks: the chain's own app
scenario tests (real proofs, the launch genesis path) recorded as RPC
`block_results` with the keepers' note, identity and stake tree sizes and
roots after each block (personhood, shielded pool, staking lifecycle,
owner-locked stake notes, self-bond compounding, private dex LP).
`zk_vectors.json` comes from the chain's Go zk packages. Both regenerate from
a chain checkout without touching it:

    bin/record-chain-fixtures.sh ../earth-network-chain
    bin/zk-vectors.sh ../earth-network-chain
