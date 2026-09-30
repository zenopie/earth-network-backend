# Akash deployment — earth gas grants

Same image as the compose deployment; only the hosting primitives differ.
`deploy.yaml` is the SDL.

## Build the image first

**Check the published image is not older than this service.** CI builds on
`v[0-9]+.[0-9]+.[0-9]+` tags only, so an untagged change is not published and
deploying the last release gets you a different program. `bin/digest.sh <tag>`
resolves a tag to the digest to pin.

    git tag v1.1.46 && git push origin v1.1.46

Then pin the digest CI publishes rather than the tag.

## The mnemonic

`GAS_WALLET_MNEMONIC` is the only real secret here, and it is deliberately not in
`deploy.yaml`. Everything in an SDL is sent to the provider hosting the lease, so
committing it would put a spendable hot key in the repository *and* hand it to a
third party; leaving it out avoids the first of those, not the second.

Substitute it into the SDL you submit, never into the file you commit:

    SDL=$(sed "s|^      - EARTH_GAS_PRICE=.*|&\n      - GAS_WALLET_MNEMONIC=$MNEMONIC|" deploy/akash/deploy.yaml)

Treat the balance as the blast radius. It is seeded with 10,000 ERTH in the
chain's genesis — enough for 100,000 grants at `DUST_UERTH=100000`, and worth
nothing outside the devnet. Do not reuse this key for anything that is.

## Endpoints

    GET  /health          hot wallet balance and grants remaining
    POST /gas/challenge   a single-use challenge to attest over
    POST /gas/ios         grant on an App Attest attestation
    POST /gas/android     grant on an Android hardware key attestation

Exposed on a mapped port, not `as: 80`. The chain repo's SDL explains why: the
provider's generated ingress hostname returned nginx 404 for ten minutes with a
ready pod, and a mapped port worked immediately.

The apps reach this only as `https://api.erth.network`, through the tunnel, so
a new lease needs no change on the apps' side.

## The host needs ADX

`earthd gas-check` links Barretenberg's prebuilt verifier, which uses ADX
(Broadwell 2014 and later, every AMD Zen). On a host without it — the Haswell
Xeon this ran on until 2026-09-30 — earthd dies with `Illegal instruction`
before printing anything, and every proof-backed grant answers 503. Akash cannot
filter bids by CPU feature, so `bin/create.py <tag> --provider <addr>` names the
provider; the chain's own provider (akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk,
AMD EPYC) is known good. Check a new host with
`earthd gas-check human <address>` in the container before closing the old lease.

Sharing a provider with the chain is fine now. It used to hang, because
`EARTH_NODE_URL` named the chain's provider hostname and NodePort, a hairpin
from inside the cluster; both URLs are the Cloudflare tunnel now.

## Watch the balance

`/health` reports `grants_remaining`. When the wallet runs dry every grant fails
after its attestation verifies, and new users are stuck at their first
transaction.

## Sizing

0.1 cpu / 256Mi / 2Gi root / 1Gi persistent, about $1/month.

The memory is measured rather than guessed: the service idles at 69 MB RSS with
the wallet built and a `/health` round trip served, so 256Mi is ~4x headroom. If
it ever does OOM, that is the first number to raise.

The persistent volume holds the replay database. Losing it does not lose money
directly — it loses the record of which SSV transaction ids were already
honoured, and every one of them becomes replayable. Closing the lease destroys
it, same as on the chain.
