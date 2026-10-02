"""What the recorded staking scenarios hold of the stake note tree.

TestPrivateStakingLifecycle and TestStakeNotesOwnerLocked are real blocks
(bin/record-chain-fixtures.sh) with shieldedstaking_stake_note events of both
kinds (chain-minted: denom, amount, spc; proof-created: ciphertext),
shieldedstaking_stake_nullifier and shieldedstaking_stake_root, and the
keeper's stake tree size and latest root after every block.
"""
from tests.privacy_fixtures import load

STAKE_SCENARIOS = ("TestPrivateStakingLifecycle", "TestStakeNotesOwnerLocked")


def _attrs(e: dict) -> dict:
    return {a["key"]: a["value"] for a in e.get("attributes") or []}


def summary(sc: dict) -> dict:
    """The stake notes, nullifiers (per height) and roots the scenario emitted."""
    notes, nfs, roots = [], [], []
    for b in sc["blocks"]:
        r = b["block_results"]
        evs = [e for tx in r.get("txs_results") or [] for e in tx.get("events") or []] + (r.get("finalize_block_events") or [])
        for e in evs:
            a = _attrs(e)
            if e["type"] == "shieldedstaking_stake_note":
                notes.append((b["height"], a))
            elif e["type"] == "shieldedstaking_stake_nullifier":
                nfs.append((b["height"], a["nullifier"]))
            elif e["type"] == "shieldedstaking_stake_root":
                roots.append((b["height"], a["root"], int(a["tree_size"])))
    return {"notes": notes, "nullifiers": nfs, "roots": roots}


def scenario(name: str = "TestPrivateStakingLifecycle") -> dict:
    return load(name)
