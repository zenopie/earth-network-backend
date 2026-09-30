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
on iOS, Play Integrity on Android — over a single-use challenge bound to the
address. A script cannot produce one. A real phone can attest for many fresh
addresses, so per-address and daily caps bound what one device can take.

## Endpoints

    POST /gas/challenge   {address}                                -> {challenge, expires_in}
    POST /gas/ios         {address, challenge, key_id, attestation}  App Attest
    POST /gas/android     {address, challenge, token}                Play Integrity
    GET  /health          hot wallet balance and how many grants are left in it

The app attests `SHA-256(base64url_decode(challenge) || address)`: as App
Attest's `clientDataHash` on iOS, and base64url-encoded as the Play Integrity
nonce on Android. Grant endpoints answer `{status, message, tx_hash?}` with 200
(sent), 202 (broadcast, unresolved), 4xx (cannot succeed as sent) or 5xx (retry).

## Running

    pip install -r requirements.txt
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC, and the service account for Android
    uvicorn main:app --host 0.0.0.0 --port 8000

Tests need no chain, no Apple and no Google: they build their own App Attest
certificate chain and stand in for Google's decoder.

    pip install -r requirements-dev.txt
    python -m pytest

## Android: the Play Integrity service account

iOS needs nothing configured beyond `IOS_APP_ID`. Android needs Google to
decode each token, which takes a service account:

1. Play Console → the app → **Release → App integrity → Play Integrity API** →
   link a Google Cloud project (create one if asked; it is free).
2. In that Cloud project: **APIs & Services** → enable **Google Play Integrity API**.
3. **IAM & Admin → Service accounts** → create one (no roles needed) → **Keys →
   Add key → JSON**.
4. Put the file's contents, or base64 of them, in `.env` as
   `GOOGLE_SERVICE_ACCOUNT_JSON`. `bin/build-sdl.py` injects it at deploy time.

Without it `/gas/android` answers 503 and iOS is unaffected. Builds that did not
come from Play (sideloaded, `assembleDebug`) are refused as
`UNRECOGNIZED_VERSION` unless `PLAY_INTEGRITY_ALLOW_UNRECOGNIZED=true`, which is
for testing only — anyone can sideload a modified APK.

## Watch the wallet

`/health` reports `grants_remaining`. When the hot wallet runs dry every grant
fails after its attestation verifies. Alert on it.
