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
  absent); /gas/transparent unchanged (GasTransparentSignal). Comments only.

## Left
- nothing (pytest: 141 passed, 2 skipped = live-earthd tests)

## Decisions
- shielded_* events unchanged in shape (bundle actions / MsgSend emit
  shielded_note / shielded_nullifier from the ante as before).
- Not indexed: dex LP events, shielded_unshield, self_bond_compounded and
  other per-msg staking events (no tree, no rate).
- Stake roots served as a full height-ordered stream (anchors in window /
  proposal snapshots), not just latest.
