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
    POST /gas/register    a shielded fee note for a registration the chain would accept
    GET  /privacy/status  chain_id, genesis and `base` for the wallet streams
    GET  /privacy/<chain_id>/<genesis>/...   the streams (see ../../README.md)

Per-client limits on /gas/register key on `CF-Connecting-IP`
(`TRUST_CF_CONNECTING_IP=true`, set in the SDL; the service defaults it to
false), grouped by IPv4 address or IPv6 /48. That is only safe because the
app is reachable solely through the tunnel: never publish port 8000 globally
while it is on, or any client picks its own key. Bodies over 64 KiB are
refused before parsing, gas-check refusals spend a per-minute budget, and
part of the queue is reserved for passports from known Document Signers
(see ../../README.md, "What runs before gas-check"). The known-DSC set is
read from `EARTH_RPC_URL` (rpc.erth.network) every 10 minutes; if that is
unreachable the lane is simply unused.

## /privacy behind Cloudflare (set this up)

The streams are public and cacheable; Cloudflare is what serves them. The
origin admits at most `PRIVACY_MAX_CONCURRENT` (4) /privacy responses in
flight (503 past it) and `PRIVACY_IP_MAX_PER_WINDOW` (240) a minute per
client (429), and takes only fixed page sizes (100, 1000) with page-aligned
cursors, so every wallet asks for the same URLs (audit-4 B3). Those bound
what one burst costs the 0.1-CPU lease; they do not stop a burst reaching
the tunnel. In the erth.network zone:

1. **Cache rule** — *Caching → Cache Rules*: `starts_with(http.request.uri.path,
   "/privacy/")` → *Eligible for cache*, *Edge TTL: use cache-control header
   if present*, *Cache key: include the query string* (all of it). The origin
   answers only the canonical spelling of a page (audit-5 M2): an unknown
   or repeated parameter, parameters out of alphabetical order (audit-6
   L4), a non-page limit or cursor, or an integer with a
   leading zero, a sign or percent-encoding is 400 no-store from the gate,
   before any handler or in-flight slot. So the cacheable key space is the
   page set, and junk spellings cost the origin a regex, not a page.
   Every /privacy response names `Access-Control-Allow-Origin:
   https://erth.network` whatever the request's Origin, so the cached copy
   is right for the web wallet and every app (Cloudflare ignores `Vary:
   Origin`); a localhost origin is reflected with `no-store`, never cached. Without
   it Cloudflare does not cache JSON and every page is a miss.
2. **Rate-limiting rule** — *Security → WAF → Rate limiting rules*:
   - If: `starts_with(http.request.uri.path, "/privacy/")`
   - Characteristics: *IP*; *Increment counter when*: `not cf.cache_status in
     {"HIT" "STALE" "UPDATING" "REVALIDATED"}` where the plan allows counting
     on the response (Pro+; on Free count every request and raise the rate)
   - Rate: **120 requests / 10 seconds** (Free: one 10 s period, which is fine)
   - Action: *Block* for 10 seconds (answers 429; wallets back off and retry)

   A first sync of 100k notes is ~100 pages of 1000, mostly cache hits, so
   that rate refuses no wallet. Change it with the origin's
   `PRIVACY_IP_MAX_PER_WINDOW` in mind: the edge rule should trip first.

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
`earthd gas-check registration < msg.json` in the container before closing the old lease.

Sharing a provider with the chain is fine now. It used to hang, because
`EARTH_NODE_URL` named the chain's provider hostname and NodePort, a hairpin
from inside the cluster; both URLs are the Cloudflare tunnel now.

## Watch the balance

`/health` reports `grants_remaining`. When the wallet runs dry every grant fails
after the registration checks out, and new users are stuck at their first
transaction.

## Sizing

0.1 cpu / 256Mi / 2Gi root / 1Gi persistent, about $1/month.

The memory is measured rather than guessed: the service idles at 69 MB RSS with
the wallet built and a `/health` round trip served, so 256Mi is ~4x headroom. If
it ever does OOM, that is the first number to raise.

The persistent volume holds the replay database and the privacy index. Losing
the replay database loses the record of which passports were granted this
month — each could be paid once more — and resets the daily cap. Closing the
lease destroys it, same as on the chain. (The index rebuilds from the chain;
after a chain relaunch, wipe it — the indexer halts on the new chain — and the
URLs move to the new genesis on their own.)
