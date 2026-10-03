# Backend: Orchard events (branch privacy/orchard)

Source of truth: chain worktree wt/chain-orch (privacy/orchard), ORCHARD_DESIGN
§12-13, x/shielded/types/events.go, x/shieldedstaking/{types/events.go,
keeper/stake_tree.go}.

Test venv: /Users/zenopie/Documents/projects/earth-network-backend/.venv/bin/python -m pytest

## Done
- Recorder: stake tree size + latest root per block; staking-env hook
  (e.scanStake()); records 6 scenarios (+ TestStakeNotesOwnerLocked,
  TestSelfBondCompounds, TestDexAnmlPoolLiquidity). SCENARIOS = every
  recorded fixture file.
- events.py: shieldedstaking_stake_note (position_id!, commitment, minted:
  denom/amount/spc | created: ciphertext), _stake_nullifier, _stake_root
  (root, tree_size; no height attr).
- store: stake_notes / stake_nullifiers / stake_roots, same checks as the
  pool (sequence, no double spend, root size).
- indexer size check includes /earth.shieldedstaking.v1.Query/StakeTree.
- verify: stake tree rebuild + minted cm check (H(TAG_STAKE, AssetID(denom),
  amount, spc)) + chain StakeTree compare; bin/verify-trees.py prints it.
- /privacy/stake/{notes,nullifiers,roots}; status + roots/latest carry stake;
  route pin test updated.
- Fixtures + zk_vectors.json re-recorded from chain-orch aa78c11 (6
  scenarios; Lifecycle and OwnerLocked carry real minted + created stake
  notes, stake nullifiers, stake roots; Dex covers private LP + EndBlock
  payout notes). tests/test_privacy_stake.py runs on them.
- zkvectors: stake_pc/stake_cm/stake tree vectors from Go, pinned in test_zk.
- Legacy tests adjusted to bundles (>= 2 actions instead of 3-in/3-out).
- gas: /gas/register unchanged (gas-check ignores MsgRegister.fee, may be
  absent). (/gas/transparent since removed, see Audit fixes.)

## Audit fixes (2026-10-02)
- Removed /gas/transparent and the device-attestation grants (/gas/ios,
  /gas/android, /gas/challenge; appattest/keyattest/challenges + certs;
  chain.send_dust; gascheck.membership; per-address cap; IOS_*/ANDROID_*/
  APP_ATTEST_ALLOW_DEVELOPMENT/CHALLENGE_* config, env, SDL; cbor2).
  build-sdl.py refuses the old keys. /gas/register is the only grant.
- /gas/register cheap checks before gas-check: per-IP window
  (CF-Connecting-IP if TRUST_CF_CONNECTING_IP), ValidateBasic bounds,
  canonical decimal signals, RegistrationBinding at address_index (Python,
  pinned to new Go vector), current_date skew, replay key
  passport:<public_signals[2]>:<YYYY-MM> (nullifier_index 2 per
  chain-orch networks/genesis.json), daily cap. One gas-check per client in
  flight (429). gas-check nullifier != ours -> 503, unclaimed.
- Daily cap is REGISTER_GRANT_MAX_PER_DAY, counting passport: ids only.
- L3: streams under /privacy/<chain_id>/<genesis16>/ (genesis = first block
  hash, meta genesis_hash, recorded once); other pairs 404 no-store;
  /privacy/status gives base. README "URL scheme for wallets".
- L4: confirmed failed-tx events indexed; comment at the tx loop + test
  marking every tx failed.
- DSC-known check not done backend-side (needs PKI state); gas-check does it
  before the proof.

## Final chain formats (chain-orch fced976, 2026-10-02)
- RegistrationBinding = H(TAG_REG, idc, pc_anml, Bytes(ct_anml), pc_erth,
  Bytes(ct_erth), affiliate); services/zk/privacy + zk_vectors (incl.
  TestRegistrationBindingPinned 0x20ce5fcc...).
- /gas/register: ciphertext_anml, ciphertext_erth, ciphertext_gas required,
  exactly 177 bytes (v2 blind). MsgShield proto unchanged (fields 1-4);
  shield_dust refuses any other length; msg_shield vector now a 177-byte
  ciphertext through ValidateBasic.
- Indexer: shielded_shield/shielded_mint carry ciphertext (checked equal to
  the shielded_note's); shieldedstaking_stake_note always carries ciphertext
  (minted: blind stake ct + denom/amount/spc). Stream columns unchanged;
  minted stake rows' ciphertext no longer null. README "Stream row changes
  for wallets".
- Fixtures re-recorded from fced976. No Groundworks/allocation events are
  indexed (none to change).

## Left
- Wallet apps must move to /privacy/status -> base (old unkeyed stream paths
  are gone) and stop calling the removed gas endpoints.
- nothing else (pytest: 142 passed, 1 skipped = live-earthd test)

## Decisions
- shielded_* events unchanged in shape (bundle actions / MsgSend emit
  shielded_note / shielded_nullifier from the ante as before).
- Not indexed: dex LP events, shielded_unshield, self_bond_compounded and
  other per-msg staking events (no tree, no rate).
- Stake roots served as a full height-ordered stream (anchors in window /
  proposal snapshots), not just latest.
