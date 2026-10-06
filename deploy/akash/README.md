# Akash deployment — earth network backend

`deploy.yaml` is the SDL. `bin/create.py` makes a new lease, `bin/deploy.sh`
updates one in place, and both submit the SDL `bin/build-sdl.py` builds:
`deploy.yaml` with the image digest and the three secrets from `.env`
(`GAS_WALLET_MNEMONIC`, `TUNNEL_TOKEN`, `CHAIN_EDGE_TOKEN`) substituted in.

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

It lives in the gitignored `.env`; `bin/build-sdl.py` substitutes it into the
SDL that is submitted, never into the file that is committed.

Treat the balance as the blast radius. The chain's genesis funds no gas
wallet: it has nothing until it is sent ERTH after launch (each grant is
`DUST_UERTH`, 0.1 ERTH; `/health` reports how many it holds). Do not reuse
this key for anything else.

## The edge token

`CHAIN_EDGE_TOKEN` is the backend's pass past the Cloudflare allowlist and rate
limits in front of the node (`services/edge.py`; the deploy repo's
`akash/README.md`, "Public RPC and LCD limits", rule 0). Without it
`rpc.erth.network` answers gas-check's JSON-RPC POSTs with 403 and every grant
fails as unavailable. Generate it once
(`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`), put it in
`.env`, and put the Authorization value it yields in the Cloudflare rule:
`printf 'earth-backend:%s' "$CHAIN_EDGE_TOKEN" | base64`, prefixed with
`Basic `. It moves no funds; whoever holds it can only skip the public limits.
To rotate, change the rule and `.env` together and redeploy in place.

## Endpoints

    GET  /health          hot wallet balance and grants remaining
    POST /gas/register    a shielded fee note for a registration the chain would accept
    GET  /gas/pow         the proof of work /gas/register needs now
    GET  /circuits/<variant>.<sha256>.json.gz   a passport circuit the wallets do not bundle
    GET  /circuits/<variant>.json.gz   the same by its plain name (5-minute cache)
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

Sharing a provider with the chain is fine: `EARTH_NODE_URL` and
`EARTH_RPC_URL` are Cloudflare tunnel hostnames, never a provider hostname
(a hairpin from inside that provider's cluster; `bin/build-sdl.py` refuses
one).

## Watch the balance

`/health` reports `grants_remaining`. When the wallet runs dry every grant fails
after the registration checks out, and new users are stuck at their first
transaction.

## Sizing

0.1 cpu / 256Mi / 2Gi root / 4Gi persistent (`deploy.yaml`).

The memory is measured rather than guessed: the service idles at 69 MB RSS with
the wallet built and a `/health` round trip served, so 256Mi is ~4x headroom. If
it ever does OOM, that is the first number to raise.

The persistent volume holds the replay database and the privacy index. Losing
the replay database loses the record of which passports were granted this
month — each could be paid once more — and resets the daily cap. Closing the
lease destroys it, same as on the chain. (The index rebuilds from the chain;
after a chain relaunch, wipe it — the indexer halts on the new chain — and the
URLs move to the new genesis on their own.)
