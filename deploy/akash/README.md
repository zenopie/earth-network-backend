# Akash deployment — earth ads-for-gas

Same image as the compose deployment; only the hosting primitives differ.
`deploy.yaml` is the SDL.

## Build the image first

**The published image is older than this service.** CI builds on
`v[0-9]+.[0-9]+.[0-9]+` tags only, and the digest currently in
`docker-compose-secretvm.yaml` is `v1.1.45`, built from a commit that predates
the ads-for-gas rewrite — it is still the Secret-era backend. Deploying it gets
you a different program.

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
chain's genesis — enough for 200,000 grants at `DUST_UERTH=50000`, and worth
nothing outside the devnet. Do not reuse this key for anything that is.

## Endpoints

    GET /health         hot wallet balance and grants remaining
    GET /ads-callback   AdMob Server-Side Verification callback

Exposed on a mapped port, not `as: 80`. The chain repo's SDL explains why: the
provider's generated ingress hostname returned nginx 404 for ten minutes with a
ready pod, and a mapped port worked immediately.

**AdMob's SSV callback URL must be updated whenever the lease changes**, since
the external port is assigned per lease. If it points at a dead port the failure
is quiet in the worst way: users watch ads, Google records a delivery, and
nothing arrives.

## `ADMOB_AD_UNIT_ID` is unset

The service starts without it and skips the ad-unit check. Fine for a devnet,
wrong for anything real — unset means a valid Google signature from *any* of
your ad units can claim a grant. Set it before this faces users.

## Watch the balance

`/health` reports `grants_remaining`. When the wallet runs dry the failure is
silent and expensive: callbacks still verify, transaction ids are still consumed,
and users watch ads for nothing.

## Sizing

0.1 cpu / 256Mi / 2Gi root / 1Gi persistent, about $1/month.

The memory is measured rather than guessed: the service idles at 69 MB RSS with
the wallet built and a `/health` round trip served, so 256Mi is ~4x headroom. If
it ever does OOM, that is the first number to raise.

The persistent volume holds the replay database. Losing it does not lose money
directly — it loses the record of which SSV transaction ids were already
honoured, and every one of them becomes replayable. Closing the lease destroys
it, same as on the chain.
