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
