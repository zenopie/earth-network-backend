# Audit history (backend, branch privacy/orchard)

What each review round found in this service, what changed, and what was
accepted and why. The README describes the current design; this file is the
record of how it got there. Finding ids (B1, M3, L6, ...) are the audit
reports' and appear in code comments where a check exists because of one.

Test counts are `python -m pytest` at the end of each round (the one skip is
the live `earthd gas-check` test, which needs a chain).

## Orchard adoption and the first audit fixes (2026-10-02)

Adoption of the Orchard-style shielded pool and the stake note tree.

- Indexer reads `shieldedstaking_stake_note`, `_stake_nullifier`,
  `_stake_root`; the store holds the stake tree with the pool's checks
  (positions in sequence, no double spend, root size); the per-batch size
  check includes `Query/StakeTree`; verify rebuilds it.
- Removed: `/gas/transparent`, the device-attestation grants (`/gas/ios`,
  `/gas/android`, `/gas/challenge`), `/gas/human`, and their settings.
  `/gas/register` is the only grant.
- `/gas/register` refuses before gas-check on everything checkable cheaply:
  per-IP window (`CF-Connecting-IP` only when `TRUST_CF_CONNECTING_IP`),
  `ValidateBasic` bounds, canonical decimal signals, the registration
  binding, the date skew, the passport replay key and the daily cap. One
  gas-check per client in flight. A nullifier from gas-check other than ours
  is 503 and nothing is claimed.
- L3: streams keyed under `/privacy/<chain_id>/<genesis16>/`; any other pair
  is 404 `no-store` (a relaunch under the same chain id cannot be served
  stale pages from a CDN).
- L4: failed-tx events are indexed (the ante's writes persist; see README).

Re-audit K4 (2026-10-02): request bodies capped at `MAX_BODY_BYTES` before
parsing (`services/bodylimit`, pure ASGI, streamed bodies cut off).

## Round 3 (2026-10-03)

- IPv6 clients keyed by a /48 (`REGISTER_IPV6_PREFIX`).
- Refusal budgets: only refusals that cost a proof verification count, per
  DSC commitment, per issuing country and network-wide. A request under a
  spent budget needs a proof of work (428 without); `services/pow`,
  `GET /gas/pow`.
- Grants once per passport in a sliding 30 days (ids `:YYYY-MM-DD`).
- Refusal logs carry the kind only (no handle, country or nullifier).
- Indexer: genesis re-checked on every prepare; a tip below the index halts
  unless the node is catching up; a skipped size check logs at WARNING;
  rates of a sweep past 200 validators keep their epoch.
- `/privacy`: one SQLite read snapshot per response
  (`poc_height_page_race.py`); integer parameters bounded to int64 (422).
- Stake nullifier tree (chain ORCHARD_DESIGN.md section 15): leaf indexes
  stored and checked, snapshots stored, `/stake/nullifier-tree` and
  `/stake/snapshots`, `Query/StakeNullifierTree` in the size check.

Accepted:
- **The gas note can be claimed from the mempool.** Someone copying a
  broadcast MsgRegister before its registrant asked for gas gets that
  passport's grant to a pc of theirs. The app asks for gas before it
  broadcasts (it pays MsgRegister's fee from that note), the registration
  itself is unaffected, and binding `pc_gas` would need a key the registrant
  does not have yet. Bounded by the daily cap.
- **A switch can re-draw a grant every 30 days.** Costs `DUST_UERTH` per
  passport per 30 days at most and is a real, fee-paying registration;
  keying on the nullifier alone would strand a holder whose first gas note
  was lost. Capped apart since round 4 (B4).
- **Whether the DSC is trusted is not checked here.** It needs the chain's
  PKI state; gas-check checks it before verifying the proof.

## Round 4

- B1: the reserved lane needs `dsc_der`'s own DSC commitment
  (`services/dsccommit`, the port of `x/pki/certs.DscCommitmentOf`, pinned
  to the chain for seven certificates including Brainpool and explicit
  P-521).
- B2: every exception after the broadcast was posted is resolved by tx hash
  (a cosmpy `RuntimeError` for a proxy's non-200 included); only a
  connection never made and a CheckTx refusal other than "already in cache"
  propagate as nothing-moved.
- B3: `/privacy` page sizes fixed (`PRIVACY_PAGE_SIZES` 100, 1000), position
  and index cursors page-aligned, `services/privacygate` (4 in flight,
  240 a minute per client), Cloudflare cache and rate-limit rules
  (deploy/akash/README.md).
- B4: switch grants capped apart (`REGISTER_SWITCH_GRANT_MAX_PER_DAY`, the
  replay row's kind column).
- B5: `current_date` values that are not calendar dates are refused, as the
  chain does.

## Round 5

- M1: the DSC commitment for the lane is hashed off the event loop, one at a
  time, cached by key, only for keys of at most 512 bytes; a mismatch is 400
  before the queue.
- M2: `/privacy` serves only the canonical spelling of a URL (unknown,
  repeated or non-decimal parameters are 400 `no-store` at the gate);
  unknown `/privacy` paths are 404 `no-store`.
- M3: signer demotion removed (anyone could trigger it with a public
  certificate); at most one priority check per DSC commitment at a time;
  every refusal counts against the client; network budget 30 -> 5 a minute
  (what the 0.1-CPU lease can verify), country 10 -> 4.
- CORS on `/privacy`: a fixed `Access-Control-Allow-Origin` (CDN-safe),
  localhost reflected with `no-store`, OPTIONS 204.
- L1 `.dockerignore`; L2 the entrypoint chowns no symlink target; L3
  `/health` served from a background reading; L4 handle directory re-read
  at most every 10 blocks, parsed in a worker thread, staged in SQLite,
  capped at 200k; L5 `handles_stale` / `stale`; L6 a halted index serves
  nothing under `{base}` and pages are immutable only up to the last
  size-checked height; L7 the `blocks` table keeps only the rows something
  reads; L9 `bin/create.py` redacts Console API errors; L11 uvicorn without
  access log or proxy headers; L12 base image by digest and a hashed
  dependency lock, wheels only; L13 `/gas/register` counts the client
  before validating the body.
- Chain round 5 formats: MsgRegister's referral is `affiliate_handle` only
  (`affiliate_pc` / `affiliate_ciphertext` refused with a 400 naming them);
  the chain mints the referral as an open note, indexed with its opening
  and served as notes format 2; the `register` event's paid referral is
  checked against its open-note mint.

Accepted:
- L8 (client keying for mobile carriers) was not changed in round 5; round
  6 M1 moved refusal counting to a /64.
- L10 is the mempool claim above.
- M2: parameter order was not canonicalised in round 5 (fixed in round 6
  L4). An omitted parameter and its explicit default remain two spellings
  of one page: bounded at two cache keys a page, and canonicalising needs
  per-endpoint defaults in the gate.

## Round 6

- M1: a client over its refusal budget is shed (proof of work at
  `POW_SHED_BITS`), not locked out; refusals counted per IPv6 /64
  (`REGISTER_CLIENT_REFUSAL_IPV6_PREFIX`) while the request window stays
  per /48; a signer's or country's daily cap does not count; an expired
  document signer certificate is refused 400 before the queue;
  `GET /gas/pow` reports shedding for a shed client.
- L1: a proof-of-work stamp is consumed before the `lane_commitment` await
  and given back only by the request that consumed it, when not relied on.
- L2: `handles_stale` measured from the first pending handle event.
- L3: cloudflared metrics on loopback only; `bin/build-sdl.py` refuses
  anything else.
- L4: `/privacy` parameters in alphabetical order.
- L5: `.dockerignore` patterns match at any depth (`**/`).
- L6: `AKASH_API_KEY` reaches curl as a header file, not argv.
- I1: dead `SendUnresolved`-without-hash branch removed. I2: `_coarse` cuts
  decimal public signals too (documented and tested; no code change). I3:
  replay rows older than 31 days pruned, at most hourly. I4:
  `actions/checkout` pinned by commit.
- Chain round 6 formats: the registration binding includes the chain id;
  `HandleEntry.owner` parsed and served as the sixth `/handles` element
  (no format number: appended); error 1127 (switch under another document
  signer) counts against the client.

Accepted:
- One check in flight and the 10-an-hour request window stay per /48, so a
  CGNAT address shares them; only refusal counting moved to /64.

## Staking formats (chain 48b631c, dff3a9b)

- Undelegations pay out by themselves: `shieldedstaking_unbond_payout` is
  checked against the block's x/shieldedstaking uerth mints (one
  ciphertext, positions distinct, summing to the amount); nothing is
  stored, the payout notes are ordinary `/notes` rows. Claim notes and the
  `unbond/` denom are gone from the chain and from the index.
- One stake note per validator: every stake note is a stake proof output
  with a 201-byte ciphertext; stake notes format 2
  `[position, height, cm, ciphertext]`; a stake note event with
  `denom`/`amount`/`spc`, or a `shieldedstaking_redelegate` with `minted`,
  halts the indexer.
- The slash debt tree: `shieldedstaking_debt_row` stored and checked (next
  leaf for a new key, its own leaf for a known one, never rising),
  `move_slashed` and `slash_debt` checked, `move_key` checked against the
  block's stake nullifiers; `Query/DebtTree` size and root compared every
  batch; `{base}/debt_rows`; verify replays every write.

## Open at the end of these rounds

- `Dockerfile` `EARTHD_VERSION` (v1.0.0) predates handles, the round-5 and
  round-6 MsgRegister and error 1127. It is bumped, with its sha256, when
  the chain cuts a release from privacy/orchard; until then gas-check from
  the image computes the old binding.
- No recorded scenario reaches a split payout, a failed payout or a
  rewritten debt row; each is tested with synthetic events in the chain's
  shape.

Test counts: 266 after round 3, 321 after handles, 363 after round 5
fixes, 379 after round 5 formats, 393 after round 6 fixes, 405 after round
6 formats, 423 after unbond payouts, 470 after the slash debt tree.

## Passport signature coverage (2026-10-04)

- dsccommit mirrors the chain's new commitments: P-224 (tag 8),
  brainpoolP224r1 (9), RSA as Poseidon2(10, e, modulus); explicit curve
  parameters name a curve only when all of them match (93e3f5b).
- `GET /circuits/<variant>.json.gz`: the 17 register circuits the wallets do
  not bundle, served byte for byte; the wallets pin their hashes (02367e4).

The precheck and the reserved lane do not depend on the variant.

## Pre-relaunch cleanup (2026-10-06)

Feature freeze, no behaviour change a wallet sees.

- The index's per-format migrations (refusals of three earlier chain
  formats, an in-place drop of a handle directory without owners) are one
  check: a table whose columns are not exactly SCHEMA's is refused, wipe
  `INDEX_DB`. A pre-owner handle directory is now refused rather than
  dropped; every such index is from a chain before the relaunch, which the
  indexer halts on anyway.
- Removed: tests asserting the removed grants stay removed, unused tree
  accessors, `BodyLimit`'s unused `max_bytes`, two unused loggers,
  cosmpy's default `faucet_url=None`.
- Deduplicated: the chain's tree query paths (indexer and verify), the
  protobuf varint encoder (handles and verify), the sliding-window bump
  (refusal budgets and client refusals).
- Docs: the launch genesis funds no gas wallet (it is funded after launch);
  earth-1 is not a devnet; ten pinned DSC certificates; requirements.txt
  describes the lock workflow.

Test count: 476 after passport signature coverage; 470 after this (the six
removed tests were the removed-grant checks).

## Round-2 chain adoption: idc proofs, used idcs, lease sweep (2026-10-06)

Chain privacy/orchard b9f840e, genesis 723549a8 (R2-B1, R2-B2, CD-1..CD-4).

- `/gas/register` takes the register proof's five public inputs
  `[current_date, address, nullifier, dsc_key, idc]`; `PASSPORT_IDC_INDEX`
  (4). After the binding, `public_signals[4]` must equal `idc` → 400 (the
  chain's 1103: the circuit computes idc from the prover's `id_secret`).
- Refusal kinds `idc used` (1130 ErrIdcUsed) and `idc mismatch` (1103's
  idc detail). Both count against the client, like 1127/1128: decided
  before the proof from public chain data, and no honest wallet meets
  either (it registers a fresh identity each time; an honest idc mismatch
  is refused 400 first). 1130's 403 says to switch to a new wallet; a chain
  idc mismatch logs `PASSPORT_IDC_INDEX` as the likely misconfiguration.
- The indexer logs x/allocation's lease alerts (`lease_retire_failed`,
  `lease_settle_held` as errors, `lease_backlog_drained` as info), never
  checks or stores them. Genesis `used_idcs` and `params.idc_index` change
  nothing here: the index reads no genesis state and no idcs.
- Fixtures re-recorded from b9f840e (no event-shape change).
- Not yet done: `circuits/` still holds the 17 pre-R2-B1 download
  circuits (they hash to the old `variants.json`). The register circuits
  changed (an `id_secret` input, an `idc` output), so all 17 must be
  replaced from mobile's `circuits/tools/variants.py build --downloads
  <backend>/circuits`, and the wallets' manifest pins the new hashes.

## Round-3 backend/deploy fixes (2026-10-06)

Audit round3-backend-deploy.md (R3-BD-1, R3-BD-3, R3-BD-4, R3-BD-6, R3-BD-7).

- `GET /gas/pow` is `async`: as a sync route it ran in Starlette's
  threadpool and pruned the ratelimit OrderedDicts concurrently with the
  loop. `ratelimit.run` survives a failing sweep and logs only the
  exception class (a message could hold an IP-derived key).
- `CHAIN_EDGE_TOKEN` (`services/edge.py`): the backend's Basic-auth
  credential at Cloudflare, sent only to `CHAIN_EDGE_HOSTS` (CometRPC and
  the cosmpy session as a header, gas-check's `--node` as userinfo). The
  deploy repo's rule 0 skips the RPC allowlist and the rate limits for it;
  `rpc.erth.network` otherwise refuses gas-check's JSON-RPC POSTs.
  `build-sdl.py` injects it from `.env` and requires it.
- `/circuits/<variant>.<sha256>.json.gz` is the only immutable name, served
  only when `circuits/SHA256SUMS` lists that hash; the plain name gets a
  5-minute cache. Wallet change to adopt it: see the fix report.
- Lease alert log lines drop the event's address and mask bech32 in the
  error (NO_LOGS policy 2 without exceptions).
- `build-sdl.py` also refuses cloudflared's `--proto-loglevel`,
  `--trace-output`, `--config` and `TUNNEL_PROTO_LOGLEVEL` /
  `TUNNEL_TRACE_OUTPUT`.

Test count: 555 (+1 skipped).
