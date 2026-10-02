"""Stake-tree events spliced into a recorded scenario.

Until the fixtures are re-recorded from a chain with the stake note tree (see
BACKEND_ORCHARD_PROGRESS.md), the stake stream is exercised on events built
here exactly as x/shieldedstaking/keeper/stake_tree.go emits them: a minted
note (position_id, commitment, denom, amount, spc), a created note
(position_id, commitment, ciphertext), a spent nullifier, and the EndBlock
root (root, tree_size). Commitments and roots are computed with services/zk,
whose stake hashing is pinned to the circuits' tags (tests/test_zk.py).
"""
import base64
import copy

from services.zk import merkle, privacy
from tests.privacy_fixtures import load

VALOPER = "earthvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
DERTH = f"derth/{VALOPER}"
UNBOND = f"unbond/{VALOPER}/3"


def _ev(type_: str, mode: str | None = None, **attrs) -> dict:
    a = [{"key": k, "value": v, "index": True} for k, v in attrs.items()]
    if mode:
        a.append({"key": "mode", "value": mode, "index": False})
    return {"type": type_, "attributes": a}


def _hx(v: int) -> str:
    return privacy.field_bytes(v).hex()


def with_stake(name: str = "TestPrivateStakingLifecycle") -> dict:
    """The scenario with two stake blocks: two mints, then a spend creating two notes."""
    sc = copy.deepcopy(load(name))
    blocks = sc["blocks"]
    tree = merkle.SparseTree()
    a, b = blocks[3], blocks[6]

    def mint(denom: str, amount: int, seed: int) -> dict:
        spc = privacy.stake_pc(privacy.owner_pk(seed), seed + 1, seed + 2)
        cm = privacy.stake_cm(privacy.asset_id(denom), amount, spc)
        pos = tree.append(cm)
        return _ev("shieldedstaking_stake_note", position_id=str(pos), commitment=_hx(cm),
                   denom=denom, amount=str(amount), spc=_hx(spc))

    def created(seed: int) -> dict:
        cm = privacy.stake_cm(privacy.asset_id(DERTH), 400 + seed, privacy.stake_pc(seed, seed, seed))
        pos = tree.append(cm)
        return _ev("shieldedstaking_stake_note", position_id=str(pos), commitment=_hx(cm),
                   ciphertext=base64.b64encode(b"stake ct %d" % seed).decode())

    def root(block: dict) -> None:
        r = _hx(tree.root())
        block["block_results"].setdefault("finalize_block_events", []).append(
            _ev("shieldedstaking_stake_root", "EndBlock", root=r, tree_size=str(tree.size)))

    res = a["block_results"]
    res["txs_results"] = (res.get("txs_results") or []) + [
        {"code": 0, "events": [mint(DERTH, 1_000_000, 11)]},
        {"code": 0, "events": [mint(UNBOND, 5, 21)]},
    ]
    root(a)
    first_root = _hx(tree.root())
    nf = _hx(privacy.H(privacy.tag("earth.snf"), 1, 2, 0))
    res = b["block_results"]
    res["txs_results"] = (res.get("txs_results") or []) + [
        {"code": 0, "events": [_ev("shieldedstaking_stake_nullifier", nullifier=nf), created(1), created(2)]},
    ]
    root(b)
    second_root = _hx(tree.root())
    for blk in blocks:
        if blk["height"] >= b["height"]:
            blk["stake_tree_size"], blk["stake_latest_root"] = 4, second_root
        elif blk["height"] >= a["height"]:
            blk["stake_tree_size"], blk["stake_latest_root"] = 2, first_root
    sc["stake"] = {"heights": [a["height"], b["height"]], "roots": [first_root, second_root], "nullifier": nf}
    return sc
