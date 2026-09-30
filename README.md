# earth gas grants

Turns an attested request from a genuine app install into enough ERTH for a new
human to make their first transaction.

## Why it exists

A new user has no ERTH and, more awkwardly, no on-chain account. An address the
chain has never seen cannot sign anything at all — the ante handler rejects an
unknown signer with `account does not exist` before it even looks at who is
paying the fee. So a fee grant is not enough; something has to put coins there.

Registration pays ERTH back out of the human allocation stream, so this is
subsidising the first transactions of each new human.

Device attestation is the Sybil defence. A grant needs proof, from Apple or
Google, that the request came from our signed app on real hardware — App Attest
on iOS, hardware key attestation on Android — over a single-use challenge
bound to the address. A script cannot produce one. A real phone can attest for many fresh
addresses, so per-address and daily caps bound what one device can take.

## Endpoints

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
