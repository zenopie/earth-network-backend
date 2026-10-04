# Backend fix 6: chain privacy/orchard 203d3b2 (audit round 5)

Chain: wt/chain-orch 203d3b2 (CHANGELOG [Unreleased] audit round 5;
ORCHARD_DESIGN.md section 16; FIX_ROUND5_PROGRESS.md). Feature freeze:
fixes and format adoption only. Baseline (5ef87bc): 363 passed, 1 skipped.

## Steps
- [x] 1 /gas/register: MsgRegister referral is affiliate_handle (15) only;
      binding affiliate field 0 or H("earth.affiliate", Bytes(handle));
      affiliate_pc / affiliate_ciphertext (11, 12) refused with a 400 naming
      them (even empty; not in the published schema); zk_vectors from
      203d3b2, with a ReferralOpening vector (c17c8b6)
- [x] 2 privacy index: open notes (shielded_mint owner_pk, rho, rcm; empty
      ciphertext) stored with their opening; verify checks each open note's
      cm from its row; an index without the opening columns refuses to open
      (wipe INDEX_DB) (13eb232)
- [x] 3 register event: handle / referral / referral_position read; a paid
      referral must name an open-note mint of its block with that amount
      (EventError otherwise); nothing of it stored (13eb232)
- [x] 4 fixtures re-recorded from 203d3b2 (bin/record-chain-fixtures.sh,
      chainrec recorder unchanged) (13eb232)
- [x] 5 notes stream format 2: [position, height, cm, ciphertext, amount,
      owner_pk, rho, rcm]; ciphertext null for an open note; "format": 2 on
      every page, "note_format": 2 in status; README "Note stream format 2"
      (14bd53b)
- [x] Split LP payouts (MintNoteSplit): every note indexed, same ciphertext
      at each position with its own amount; already handled by the parser
      (notes keyed by position), now tested (tests/test_open_notes.py)

## Notes
- No per-owner lookup: wallets match open notes locally by owner_pk over the
  rows they already download.
- TestPrivatePersonhood's C2 and D1 referral mints are checked end to end:
  opening = ReferralOpening(nullifier, leaf_index) from the register event,
  cm recomputed from the served row.
- No recorded scenario reaches a split payout (the chain covers it in the
  x/dex keeper test audit5_payout_test.go); the split tests are synthetic
  events in MintNoteSplit's shape.

## Left
- Dockerfile EARTHD_VERSION (v1.0.0) is bumped at release, with its sha256,
  once the chain cuts a release from privacy/orchard: gas-check from the
  pinned binary does not know the round-5 MsgRegister.
- Wallets: send affiliate_handle only; read notes rows by `fields`, refuse a
  page whose format is not 2, match open notes by owner_pk, and treat every
  row of a split payout as its own note.

pytest: 379 passed, 1 skipped (live-earthd test).

---

# Audit round 6 fixes (backend)

Report: audit6-backend.md (privacy/orchard @ 45dfae3). Feature freeze:
fixes only. Baseline (45dfae3): 379 passed, 1 skipped.

## Steps
- [x] M1 shared-network lockout: a client over its refusal budget is shed
      (428, proof of work at POW_SHED_BITS) instead of a hard 429; client
      refusals counted per IPv6 /64 (REGISTER_CLIENT_REFUSAL_IPV6_PREFIX),
      the request window stays /48; a daily cap ("rate cap") does not count;
      an expired dsc_der is refused 400 in the precheck (no gas-check, not
      counted); GET /gas/pow reports shedding for a shed client;
      tests/test_audit6.py (auditor's /48 and CGNAT scenarios) (ce6f0dd)
- [x] L1 PoW stamp consumed right after check (before the lane_commitment
      await) and given back only by the request that consumed it, when not
      relied on (ordinary lane, dsc_der mismatch 400) (47565f6)
- [x] L2 handles_stale measured from the first pending handle event
      (meta handles_pending_height, set by apply when unset, cleared by
      commit_handles when the snapshot covers it; old index falls back to
      handles_changed_height) (9b0c8f6)
- [x] L3 cloudflared --metrics 127.0.0.1:2000 (port 2000 stays the
      required global service, answering nothing); bin/build-sdl.py refuses
      a non-loopback --metrics (e67eb20)
- [x] L5 .dockerignore patterns `**/` (any depth, root included) (debe141;
      its test made Docker-faithful in 651ebb5)
- [x] L6 AKASH_API_KEY to curl as `-H @file` (umask 077, the 700 work
      dir), not argv (345eab2)
- [x] L4 /privacy parameters in alphabetical order (from_* before limit,
      which the web and mobile wallets already send); an omitted default vs
      the explicit default is left (needs per-endpoint defaults in the gate;
      bounded at two keys per page) (5d3a718)
- [x] I1 dead SendUnresolved-without-hash branch removed (46113bc)
- [x] I2 _coarse: the hex pattern already cuts 16+ digit decimal runs;
      documented and tested, no code change (0c14094)
- [x] I3 replay rows older than 31 days pruned in claim(), at most once an
      hour (_paid_today already used the granted_at index, not a scan) (e272182)
- [x] I4 actions/checkout pinned to 11d5960a (v4.4.0, the commit v4 points
      at); the only third-party action (2004b10)

## Notes
- M1(c): an expired passport cannot be proven (the circuit proves expiry >=
  current_date), so it never reaches gas-check as its own refusal; the
  user-state refusals that do are a daily cap (not counted) and an expired
  document signer (x/pki ErrCertExpired, checked before the certificate
  chains, so mintable from a made-up certificate; refused 400 in the
  precheck instead of uncounted at gas-check). Every other kind (binding
  used, replay, revoked, ...) is mintable from public chain data and still
  counts.
- The one-check-in-flight rule and the 10-an-hour request window stay per
  /48 (CGNAT shares them); only refusals moved to /64.
- Test fixes: f90f3aa (a with_pow stamp clears the shed bits 1 time in 4),
  cc135e4 (a pre-existing ~5% race in test_queue, present at 45dfae3).

## Left
- Wallets: a 428 can now also mean "this network has too many refusals";
  the existing 428 handling (stamp at pow.bits, retry) covers it. GET
  /gas/pow reports shedding for such a client. /privacy query parameters
  must be in alphabetical order (the web and mobile wallets already are).

pytest: 393 passed, 1 skipped (live-earthd test); full suite run 4x clean.

---

# Chain audit round 6 format adoption (backend)

Chain: wt/chain-orch privacy/orchard f4a217c (CHANGELOG [Unreleased] audit
round 6; FIX_ROUND6_PROGRESS.md; personhood protos). Feature freeze: format
adoption only. Baseline (ac9fa11): 393 passed, 1 skipped.

## Steps
- [x] Registration binding H(TAG_REG, Bytes(chain_id), idc, pc_anml,
      Bytes(ct_anml), pc_erth, Bytes(ct_erth), affiliate), chain id
      EARTH_CHAIN_ID, in the /gas/register precheck; zk_vectors from f4a217c
      (reg pinned 148b3513...4159, other_chain vector); README (7471e53,
      30f9483)
- [x] HandleEntry.owner (6) parsed; 64 lowercase hex or "" else Malformed
      (the snapshot is kept) (7471e53)
- [x] /handles rows [handle, address, status, expires_at, renewal_until,
      owner]; "fields" names six; README; an index whose handles table has
      no owner column drops the snapshot (not history) and re-reads it
      (2f5542e)
- [x] 1127 ErrSwitchSignerMismatch: refusal kind "switch signer", counted
      against the client (checked before the proof, mintable from public
      data) (cbfbd68)
- [x] handle_bound / handle_released / handle_moved owner, previous_owner:
      documented; not parsed (the Handles query is the source) (1f29fb6)
- [x] Fixtures re-recorded from f4a217c; test that each directory owner is
      its latest handle event's owner (1cfa85d)

## Notes
- No handle stream format number: owner is appended, a reader of the first
  five is unaffected, and the wallets (mobile-orch d8780ce, Android and iOS)
  read row[5] only when present. Owner "" means never claimed (or, from an
  old backend, unknown); the wallets adopt nothing on it.
- MsgClaimUnbonding is still documented as before (staking redesign not
  anticipated).

## Left
- Dockerfile EARTHD_VERSION (v1.0.0) bumped at release: gas-check from the
  pinned binary computes the old binding and does not know 1127.
- Web wallet (app-orch src/chain/handles.js) does not read owner yet (its
  LCD Query/Handles path maps five fields).

pytest: 405 passed, 1 skipped (live-earthd test); full suite run 3x clean.

---

# Chain staking wave format adoption (backend)

Chain: wt/chain-orch privacy/orchard 48b631c (ORCHARD_DESIGN.md section 18;
CHANGELOG [Unreleased]; STAKING_WAVE_PROGRESS.md; shieldedstaking protos).
Feature freeze: format adoption only. Baseline (831008d): 405 passed, 1
skipped.

## Steps
- [x] Fixtures re-recorded from 48b631c (bin/record-chain-fixtures.sh); the
      recorder hooks after the block helper's Commit (the staking env's
      helper changed) and adds TestStakeVoteManyNotesOneWeight. Stake notes
      are derth/ only; the failed-claim test removed; the repeated-index
      test moved to the vote scenario (the lifecycle now spends one stake
      nullifier) (f9a15a1)
- [x] shieldedstaking_unbond_payout parsed and checked: its positions are
      this block's shieldedstaking uerth mints, distinct, not another
      payout's, one ciphertext, summing to amount; notes = len(positions);
      amount 0 iff no positions. Nothing stored: the payout notes are
      ordinary kind-2 rows of notes format 2. Tests: the recorded lifecycle
      payout row in /notes, synthetic split payouts (parse and stream),
      nine refusals, payout_failed ignored, vote_nullifiers not in the stake
      nullifier tree (tests/test_unbond_payouts.py) (5cc8202)
- [x] Docs: events.py, routers/privacy.py, services/zk/privacy.py, README
      "Undelegation payouts and four-note votes (chain 48b631c)": no stream
      format change; claim notes, the unbond/ denom, ante-claim nullifiers
      removed; split payouts are 2^63-1 a note (80322f6)
- [x] zk_vectors regenerated from 48b631c: unchanged

## Notes
- No stream format change (notes stay format 2, stake rows unchanged).
- The stake_vote event's vote_nullifiers lists the used slots only (1..4
  entries), not four with zeros (the msg has four; the chain stores and
  emits the used ones). Votes are not indexed.
- Undelegate (epoch, payout_id), matured (validator, epoch) and
  payout_failed are not read; they change no tree.
- No recorded scenario has a split unbond payout (a payout is at most the
  undelegation's value, refused above 2^63-1 at start, so a split needs
  payout > requested) or a failed one (TestUnbondPayoutsSweepRetryNeverDrop
  drives msgs outside blocks, so it is not recordable); both are synthetic
  tests in the chain's event shape.

## Left
- Dockerfile EARTHD_VERSION bumped at release (unchanged reason).
- Wallets: drop claim flow and unbond/ note scanning; find payouts by trial
  decryption of /notes (split ones: every row with the ciphertext); vote
  with four slots.

pytest: 423 passed, 1 skipped (live-earthd test); full suite run 3x clean.
