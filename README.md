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

Device attestation is the Sybil defence. A grant needs proof, from Apple or
Google, that the request came from our signed app on real hardware — App Attest
on iOS, hardware key attestation on Android — over a single-use challenge
bound to the address. A script cannot produce one. A real phone can attest for many fresh
addresses, so per-address and daily caps bound what one device can take.

## Endpoints

    POST /gas/register    {proof, public_signals, signature_algorithm, dsc_der,
                           idc, pc_anml, pc_erth, ciphertext_anml?, ciphertext_erth?,
                           affiliate?, pc_gas, ciphertext_gas?}

What the apps call. It takes the MsgRegister the app is about to broadcast
(bytes as standard base64, its fee transfer left out) and, if the chain would
accept it, shields `DUST_UERTH` from the hot wallet into a note to `pc_gas` (a
`MsgShield`; `ciphertext_gas` is emitted for the app's own trial decryption).
The app then broadcasts MsgRegister paying its fee from that note. Once per
passport per month, keyed `passport:<nullifier>:<YYYY-MM>`; the replay table
stores that key and nothing else — no address, no pc. The check is the
chain's own, through `earthd gas-check registration` (installed in the image
from the chain release; see the Dockerfile). Proofs are verified here, never by
the node.

    POST /gas/transparent {address, proof, root, nullifier, max_activation, month?}

For a registered human who wants transparent ERTH (fees from an ordinary
account). A membership proof (bytes base64) that its prover holds a live
identity leaf, with scope `GasScope(YYYYMM) = H(TAG_SCOPE, Bytes("gas"),
YYYYMM)`, signal `H(TAG_SIGNAL, Bytes("earth.gas.transparent"),
Bytes(chain_id), Bytes(address bytes))`, no exclusions, and `max_activation`
at most now; `month` must be the current UTC month. Checked by `earthd
gas-check membership` against an identity root inside the chain's window,
then `DUST_UERTH` is bank-sent to `address`. Once per nullifier per month,
keyed `gas-transparent:<nullifier>:<YYYY-MM>` with no address stored: the
backend never learns which human asked.

`/gas/human` is gone: nothing on chain links an address to a registration any
more, and a registered human pays every fee from their reward note.

The device-attestation endpoints below predate these and stay until the app
builds that call them are retired:

    POST /gas/challenge   {address}                                -> {challenge, expires_in}
    POST /gas/ios         {address, challenge, key_id, attestation}  App Attest
    POST /gas/android     {address, challenge, chain}                Key Attestation
    GET  /health          hot wallet balance and how many grants are left in it

The app attests `SHA-256(base64url_decode(challenge) || address)`: as App
Attest's `clientDataHash` on iOS, and as the attestation challenge of a fresh
AndroidKeyStore key on Android, whose certificate chain (leaf first, base64 DER)
is what it sends. Grant endpoints answer `{status, message, tx_hash?}` with 200
(sent), 202 (broadcast, unresolved), 4xx (cannot succeed as sent) or 5xx (retry).

## Running

    pip install -r requirements.txt
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC, or GAS_ENABLED=false
    uvicorn main:app --host 0.0.0.0 --port 8000

Tests need no chain, no Apple and no Google: they build their own attestation
certificate chains under roots they generate, and replay recorded chain blocks
for the indexer.

    pip install -r requirements-dev.txt
    python -m pytest

## Android: key attestation

Nothing to sign up for. The phone's secure hardware certifies a fresh key whose
certificate carries the challenge, the boot state, and the package name and
signing-certificate digest of the app that asked; the chain ends at one of
Google's public hardware-attestation roots (`services/certs/`). The backend
checks it locally and fetches only Google's public revocation list.

It needs `ANDROID_SIGNING_CERT_SHA256`: the SHA-256 of every certificate the
APK is signed with. That is the release key for sideloaded builds and, when
Play App Signing is on, Play's app-signing key for Play installs (Play Console →
Test and release → App integrity → App signing). Unset, `/gas/android` answers
503.

Refused: phones whose keys are only in software, phones with an unlocked
bootloader (`ANDROID_REQUIRE_LOCKED_BOOTLOADER`), and any APK signed with a
certificate not on the list — so a modified, re-signed app gets nothing.

## Watch the wallet

`/health` reports `grants_remaining`. When the hot wallet runs dry every grant
fails after its attestation verifies. Alert on it.

## Privacy indexer

Wallets on the shielded chain never ask anyone about their own notes. They
download every note commitment and ciphertext, every nullifier and every
identity leaf, rebuild both trees locally and trial-decrypt. This serves that
data, and nothing narrower: there is no endpoint keyed by anything a wallet
derives from its keys.

    GET /privacy/status                               synced height, counts, halted reason
    GET /privacy/notes?from_pos=&limit=               [position, height, cm, ciphertext, amount]
    GET /privacy/nullifiers?from_height=&limit=       [[height, [nf, ...]], ...]
    GET /privacy/identity?from_index=&limit=          [index, height, leaf, zeroed_height]
    GET /privacy/identity/zeroed?from_height=&limit=  [[height, [index, ...]], ...]
    GET /privacy/roots/latest                         note and identity roots, size, height, time
    GET /privacy/rates?epoch=                         [validator, rate, supply, epoch, height]

Compact JSON (rows as arrays, field order in `fields`), gzip'd. Pages default
to 1000 rows and cap at `PRIVACY_PAGE_MAX` (5000). Height-paged streams never
split a block, so `next_height` is always a clean cursor. A page that filled
its limit covers a closed range and is served `immutable`; the tip page,
identity leaves (zeroable later), roots, rates and status get short max-ages.
`amount` is set only for notes whose value is already public (a shield or a
module mint). A wallet that has synced identity leaves follows
`/identity/zeroed` rather than re-reading them.

### How it follows the chain

`services/privacy/indexer.py` reads `block_results` over CometBFT RPC from
`INDEXER_START_HEIGHT` (default: the node's earliest block), in batches, and
applies each block to SQLite (`INDEX_DB`) in one transaction with the height
it reaches — so it resumes exactly where it stopped and re-applying a block is
a no-op. CometBFT blocks are final, so it only moves forward. Run it inside
the API process (`INDEXER_ENABLED=true`) or alone:

    python -m services.privacy.indexer

Events it reads (privacy/main): `shielded_note`, `shielded_nullifier`,
`shielded_root`, `shielded_shield`/`shielded_mint` (public amounts),
`identity_leaf` (append, or zero when the leaf is all zeros),
`identity_root`, `shieldedstaking_epoch_validator` and
`shieldedstaking_epoch`. Block events are ordered PreBlock/BeginBlock, txs,
EndBlock (the SDK's `mode` attribute), which is the order notes are appended.

**Failed txs are read too.** A private tx's notes and nullifiers are written in
the ante. SDK v0.53 commits the ante's writes before running the msgs and,
when a msg fails, still returns the ante's events (only those) in the failed
tx's result; a tx whose ante fails writes nothing and returns no events. So
every event in every tx result is state that persisted, whatever the code.
(`bin/sdkcheck`, run in the SDK v0.53.6 baseapp test harness, confirms it.)

It refuses, and halts until an operator steps in, rather than serve trees that
cannot match the chain: a note position out of sequence, a nullifier twice, a
root event whose size differs from the index, a different chain id or block
hash behind the RPC than the one indexed, or tree sizes that differ from the
chain's own (`Query/Tree`, `Query/IdentityTree` at each batch's last height —
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

rebuilds both trees from the index with Python Poseidon2 (`services/zk`, a
port of the chain's `zk/poseidon2`, `zk/merkle` and `zk/privacy`), checks the
latest root of each (every recorded root with `--all-roots`) against the root
events the chain emitted, and compares the rebuilt trees with the chain's own
at the synced height. Exit 0 all match, 1 mismatch, 2 the chain could not be
asked.

### Fixtures

`tests/fixtures/privacy/Test*.json.gz` are real blocks: the chain's own app
scenario tests (real proofs, the launch genesis path) recorded as RPC
`block_results` with the keepers' tree sizes and roots after each block.
`zk_vectors.json` comes from the chain's Go zk packages. Both regenerate from
a chain checkout without touching it:

    bin/record-chain-fixtures.sh ../earth-network-chain
    bin/zk-vectors.sh ../earth-network-chain
