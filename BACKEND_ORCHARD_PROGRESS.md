# Backend: Orchard events (branch privacy/orchard)

Source of truth: chain worktree wt/chain-orch (privacy/orchard), ORCHARD_DESIGN
§12-13, x/shielded/types/events.go, x/shieldedstaking/{types/events.go,
keeper/stake_tree.go}.

Test venv: /Users/zenopie/Documents/projects/earth-network-backend/.venv/bin/python -m pytest

## Done
- Recorder: stake tree size + latest root per block; staking-env hook
  (e.scanStake()); records 6 scenarios (+ TestStakeNotesOwnerLocked,
  TestSelfBondCompounds, TestDexAnmlPoolLiquidity).

## Left
- events.py: shieldedstaking_stake_note/nullifier/root
- store: stake_notes, stake_nullifiers, stake_roots
- /privacy/stake/{notes,nullifiers,roots}; route pin test
- verify-trees: stake tree; check_sizes vs Query/StakeTree
- re-record fixtures; gas confirm; README

## Decisions
- shielded_* events unchanged in shape (MsgSend/bundle actions emit
  shielded_note / shielded_nullifier from the ante as before).
