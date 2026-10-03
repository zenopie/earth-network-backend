# Backend fix 5: chain privacy/orchard 4a663d5 (handles, predecessor_at)

Chain: wt/chain-orch 4a663d5 (CHANGELOG [Unreleased]: handles replace
public referrer addresses; predecessor-aware activation; error codes
1120-1126). Baseline: pytest 266 passed, 1 skipped.

## Steps
- [x] A zk: identity_leaf(.., predecessor_at), affiliate_field; zk_vectors
      re-generated from 4a663d5
- [x] B /gas/register: affiliate_handle / affiliate_pc / affiliate_ciphertext
      (all or none), referrer address gone; refusal kinds for 1120-1126
- [x] C fixtures re-recorded from 4a663d5 (recorder also records the
      Handles query per block)
- [x] D handle directory stream {base}/handles
- [x] E referral-mint note indexed (test on the C2/D1 registrations)

## Notes
- Membership public inputs (max_activation, max_predecessor): the backend
  builds and checks none (no membership proof passes through it; the
  reserved lane reads only the passport proof's signals 0..3, whose layout
  is unchanged). Identity leaves are served as the chain emits them; the
  Python identity_leaf (verify / vectors only) takes predecessor_at.
- Error codes: the backend has no code table; gas-check returns error text.
  _REFUSAL_KINDS gains 1120 (identity tree full) and 1121 (not a live
  handle); 1123/1124 annotated. 1122/1125/1126 and dex 1120 belong to msgs
  no registration check reaches.
- Referral-mint note: MintNote emits shielded_note + shielded_mint as every
  chain mint; indexed with no change (test on C2/D1 in
  TestPrivatePersonhood).
- Fixtures: bin/record-chain-fixtures.sh and bin/zk-vectors.sh at 4a663d5
  (they use the chain's committed proof fixtures; the chain's own
  scripts/*-fixtures.sh were already re-run in af30f73 / 6e5924f).

## Left
- Dockerfile EARTHD_VERSION (v1.0.0) predates handles: gas-check from that
  binary does not know affiliate_handle/pc/ciphertext. Bump it (and its
  sha256) once the chain cuts a release from privacy/orchard.
- Wallets: read {base}/handles whole (restart on a height change); send
  affiliate_handle/affiliate_pc/affiliate_ciphertext to /gas/register,
  never an address.

pytest: 321 passed, 1 skipped (live-earthd test).

---

# Audit round 5 fixes (scratchpad audit5-backend.md)

Baseline: 321 passed, 1 skipped. Regressions in tests/test_audit5.py (the
PoCs of scratchpad/a5/test_poc_a5.py, now refused).

## Steps
- [x] M1 DSC commitment: key capped at 512 B, worker thread one at a time,
      cached by (tag, key), mismatch 400 before the queue
- [x] M3 signer demotion removed: one priority check per DSC commitment;
      every refusal counts per client (3/h, then 429 before the queue);
      network budget 30 -> 5 a minute, country 10 -> 4
- [x] M2 PrivacyGate canonical URLs (400 no-store); unknown /privacy paths 404
      no-store at the gate
- [x] CORS on /privacy: fixed ACAO https://erth.network on every /privacy
      response (CDN-safe), localhost reflected with no-store; OPTIONS 204
- [x] L13 /gas/register validates its body after counting the client (422s count)
- [x] L1 .dockerignore, L2 chown(follow_symlinks=False), L11 --no-access-log
      --no-proxy-headers
- [x] L9 create.py redacts Console API errors (deploy.sh's rule, and a
      mnemonic's words past the first space)
- [x] L12 base image by digest; requirements.lock (51 packages, all hashes,
      bin/lock-requirements.py) installed --require-hashes --only-binary;
      build-essential dropped (every package has a wheel)
- [x] L3 /health serves a background reading (every 30 s), cacheable
- [x] L6 halted index: 503 no-store on {base}/*; pages immutable only up to
      meta verified_height (set after the tree-size check passes)
- [x] L7 blocks table keeps the last block and identity-leaf heights only
      (pruned per block, and on open for an older index)
- [x] L4 handle refresh: at most every 10 blocks, pages parsed in a worker
      thread and staged in SQLite (memory: one page), swapped whole; cap
      1M -> 200k; size from meta, not COUNT(*)
- [x] L5 handles_stale (status) / stale (stream) once 30 blocks behind a
      handle event; the indexer logs a warning while stale

## Notes
- M3 network budget: ~10 s an earthd run on the 0.1-CPU lease is an
  estimate (not timed here), so ~6 verifications a minute; budget 5.
- M3 chose both options: one priority check per DSC commitment (a second
  takes the ordinary lane, never refused) and every refusal per client.
  Cheap priority-lane refusals no longer spend the signer's budget either
  (they were attacker-triggerable the same way); failed proofs still do.
- M1: only a definite mismatch is 400; an unparseable certificate or a key
  past 512 B takes the ordinary lane unhashed (the chain decides).
- M2: parameter order is not canonicalised (at most 2 spellings a page).
  Unknown /privacy paths are 404 no-store at the gate.
- CORS: ACAO is fixed to https://erth.network on every /privacy response
  (Cloudflare ignores Vary: Origin, so a reflected origin would be cached
  for everyone); localhost origins are reflected with no-store. A dev page
  on localhost reading production through the CDN gets cached pages with
  the erth.network origin: point dev at a local backend.
- L6: immutability now also waits for the tree-size check (meta
  verified_height); with the check skipped (state pruned) pages stay TIP.
- L13: /gas/register parses its body itself; OpenAPI keeps the schema via
  openapi_extra.
- L12: requirements.lock regenerated by bin/lock-requirements.py (needs
  PyPI); verified by downloading all 51 wheels with --require-hashes for
  linux/amd64 cp311. The image was not built here (no docker).
- Not changed: L8 (client keying for mobile carriers) and L10 (pc_gas not
  bound by the proof), not in this round's brief.
- The three PoCs in scratchpad/a5/test_poc_a5.py now fail as intended.

pytest: 363 passed, 1 skipped (live-earthd test).
