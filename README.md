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
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC
    uvicorn main:app --host 0.0.0.0 --port 8000

Tests need no chain, no Apple and no Google: they build their own attestation
certificate chains under roots they generate.

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
