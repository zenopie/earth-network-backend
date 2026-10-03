"""What the recorded staking scenarios hold of the stake note tree.

TestPrivateStakingLifecycle and TestStakeNotesOwnerLocked are real blocks
(bin/record-chain-fixtures.sh) with shieldedstaking_stake_note events of both
kinds (chain-minted: denom, amount, spc; proof-created: ciphertext),
shieldedstaking_stake_nullifier (with its leaf index in the stake nullifier
tree) and shieldedstaking_stake_root, and the keeper's stake tree and stake
nullifier tree sizes and roots after every block. TestStakeVoteConcurrentProposals
adds proposal snapshots (shieldedstaking_snapshot) and stake votes.
"""
from tests.privacy_fixtures import load

STAKE_SCENARIOS = ("TestPrivateStakingLifecycle", "TestStakeNotesOwnerLocked", "TestStakeVoteConcurrentProposals")
# Proposals snapshotted (shieldedstaking_snapshot, with nf_root / nf_size)
# after a stake nullifier was spent, then stake votes and later spends.
VOTE_SCENARIO = "TestStakeVoteConcurrentProposals"


def _attrs(e: dict) -> dict:
    return {a["key"]: a["value"] for a in e.get("attributes") or []}


def summary(sc: dict) -> dict:
    """The stake notes, nullifiers (per height), roots and snapshots the scenario emitted.

    nf_index is [(leaf index, nullifier, height)] in emission order.
    """
    notes, nfs, roots, nf_index, snaps = [], [], [], [], []
    for b in sc["blocks"]:
        r = b["block_results"]
        evs = [e for tx in r.get("txs_results") or [] for e in tx.get("events") or []] + (r.get("finalize_block_events") or [])
        for e in evs:
            a = _attrs(e)
            if e["type"] == "shieldedstaking_stake_note":
                notes.append((b["height"], a))
            elif e["type"] == "shieldedstaking_stake_nullifier":
                nfs.append((b["height"], a["nullifier"]))
                nf_index.append((int(a["index"]), a["nullifier"], b["height"]))
            elif e["type"] == "shieldedstaking_snapshot":
                snaps.append((b["height"], a))
            elif e["type"] == "shieldedstaking_stake_root":
                roots.append((b["height"], a["root"], int(a["tree_size"])))
    return {"notes": notes, "nullifiers": nfs, "roots": roots, "nf_index": nf_index, "snapshots": snaps}


def scenario(name: str = "TestPrivateStakingLifecycle") -> dict:
    return load(name)
