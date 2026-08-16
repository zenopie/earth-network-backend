# earth ads-for-gas

Turns a verified rewarded-ad view into enough ERTH for a new human to make their
first transaction.

## Why it exists

A new user has no ERTH and, more awkwardly, no on-chain account. An address the
chain has never seen cannot sign anything at all — the ante handler rejects an
unknown signer with `account does not exist` before it even looks at who is
paying the fee. So a fee grant is not enough; something has to put coins there.

Registration pays ERTH back out of the human allocation stream, so this is
subsidising exactly one transaction per human, ever.

The ad is the Sybil defence. A grant needs a completed ad view attested by
Google's signature and deduped by `transaction_id`, so an attacker has to burn
real ad inventory per address — and it pays for itself rather than draining a
faucet.

## Endpoints

    GET /ads-callback   AdMob Server-Side Verification callback (called by Google)
    GET /health         hot wallet balance and how many grants are left in it

## Running

    pip install -r requirements.txt
    cp example.env .env      # fill in GAS_WALLET_MNEMONIC and ADMOB_AD_UNIT_ID
    uvicorn main:app --host 0.0.0.0 --port 8000

Point AdMob's SSV callback URL at `https://<host>/ads-callback`. The app sets the
wallet address as `custom_data` (see `HostActivity.showRewardedAd`).

## Watch the wallet

`/health` reports `grants_remaining`. When the hot wallet runs dry the failure is
quiet and expensive: callbacks still verify, ids are still consumed, and users
watch ads for nothing. Alert on it.
