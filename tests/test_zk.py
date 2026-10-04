"""Python Poseidon2, tree and derivations against the chain's Go reference.

zk_vectors.json was produced by running the chain's own zk/poseidon2,
zk/merkle and zk/privacy packages (privacy/main worktree) — see the README's
"Verifying the trees" section. The decimal vectors are the ones the chain's
poseidon2_test.go pins to @zkpassport/poseidon2 (== the Noir circuits).
"""
import json
import os

import pytest

from services.zk import debt, indexed, merkle, poseidon2, privacy

VEC = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "privacy", "zk_vectors.json")))


def hx(v: int) -> str:
    return privacy.field_bytes(v).hex()


def test_poseidon2_matches_noir_vectors():
    h = poseidon2.hash_fields
    assert h([1, 2]) == 1594597865669602199208529098208508950092942746041644072252494753744672355203
    assert h([0, 0]) == 5151499478991301833156025595048985053689893395646836724335623777508747990769
    assert h([1, 2, 3]) == 16068223842875184682212183064520144190817798559788034419026031423767658184152
    assert h([7]) == 18970562573323469175826317522388366048919495891674176618661784039580387947468
    assert h([1] * 64) == 14295874367757759963211553815049736916613748207586589166074199566751511576828
    assert poseidon2.hash2(1, 2) == h([1, 2])
    assert hx(h([1, 2, 3, 4, 5])) == VEC["hash_5"]


def test_empty_root_and_assets():
    assert hx(merkle.ZERO[32]) == VEC["zero32"]
    assert hx(privacy.asset_id("uerth")) == VEC["asset_uerth"]
    assert hx(privacy.asset_id("uanml")) == VEC["asset_uanml"]
    assert hx(privacy.asset_id(VEC["asset_long"]["denom"])) == VEC["asset_long"]["id"]


def test_commitments_and_leaves():
    pc = privacy.pc(privacy.owner_pk(42), 7, 9)
    assert hx(pc) == VEC["pc"]
    assert hx(privacy.cm(privacy.asset_id("uerth"), 100000, pc)) == VEC["cm_uerth_100000"]
    leaf = privacy.identity_leaf(privacy.idc(11), 12, privacy.country_field("DE"), 1700000000, 0)
    assert hx(leaf) == VEC["identity_leaf_DE"]
    # predecessor_at (the switch or re-entry that made the leaf) is in it.
    pred = privacy.identity_leaf(privacy.idc(11), 12, privacy.country_field("DE"), 1700000000, 1690000000)
    assert hx(pred) == VEC["identity_leaf_DE_pred"] != VEC["identity_leaf_DE"]
    assert privacy.country_field("DE") == 0x4445
    assert privacy.country_field("de") == 0 and privacy.country_field("") == 0


def test_note_tree_roots_after_each_append():
    t = merkle.SparseTree()
    for i, want in enumerate(VEC["note_roots"]):
        cm = privacy.cm(privacy.asset_id("uerth"), 1000 + i, privacy.pc(100 + i, 200 + i, 300 + i))
        assert hx(cm) == VEC["note_cms"][i]
        t.append(cm)
        assert hx(t.root()) == want


def test_identity_tree_with_a_zeroed_leaf():
    t = merkle.SparseTree()
    for i, leaf in enumerate(VEC["identity_leaves"]):
        want = privacy.identity_leaf(privacy.idc(500 + i), 600 + i, privacy.country_field("UT"), 1700000000 + i, i * 1000)
        assert hx(want) == leaf
        t.append(want)
    assert hx(t.root()) == VEC["identity_root_3"]
    t.update(1, 0)
    assert hx(t.root()) == VEC["identity_root_zeroed1"]


def test_batched_root_equals_incremental():
    a, b = merkle.SparseTree(), merkle.SparseTree()
    for i in range(37):
        a.append(i + 1)
        a.root()
        b.append(i + 1)
    assert a.root() == b.root()


def test_field_from_bytes_refuses_non_canonical():
    import pytest

    with pytest.raises(ValueError):
        privacy.field_from_bytes(poseidon2.P.to_bytes(32, "big"))
    with pytest.raises(ValueError):
        privacy.field_from_bytes(b"\x01" * 31)
    assert privacy.field_from_bytes((poseidon2.P - 1).to_bytes(32, "big")) == poseidon2.P - 1


def test_stake_tags_match_the_circuits():
    # circuits/privacy_core/src/lib.nr (mobile privacy/orchard) and
    # zk/privacy/privacy.go: TAG_STAKE "earth.stake", TAG_SPC "earth.spc".
    assert privacy.TAG_STAKE == 0x65617274682e7374616b65
    assert privacy.TAG_SPC == 0x65617274682e737063


def test_stake_commitments_and_tree():
    spc = privacy.stake_pc(privacy.owner_pk(42), 7, 9)
    assert hx(spc) == VEC["stake_pc"]
    d = VEC["stake_cm_derth"]
    assert hx(privacy.stake_cm(privacy.asset_id(d["denom"]), int(d["amount"]), spc)) == d["cm"]
    # The slash label (chain dff3a9b): StakeCM's fifth input.
    v = VEC["stake_label"]
    label = privacy.stake_label(int(v["move_key"], 16), int(v["move_time"]), int(v["exposed"]))
    assert hx(label) == v["label"]
    d = VEC["stake_cm_labelled"]
    assert hx(privacy.stake_cm(privacy.asset_id(d["denom"]), int(d["amount"]), spc, label)) == d["cm"]
    t = merkle.SparseTree()
    for i, want in enumerate(VEC["stake_roots"]):
        cm = privacy.stake_cm(privacy.asset_id(VEC["asset_long"]["denom"]), 10 + i, privacy.stake_pc(700 + i, 800 + i, 900 + i))
        assert hx(cm) == VEC["stake_cms"][i]
        t.append(cm)
        assert hx(t.root()) == want


def test_registration_binding_matches_go():
    v = VEC["registration_binding"]
    cid = v["chain_id"]
    idc_, a, e = (int(v[k], 16) for k in ("idc", "pc_anml", "pc_erth"))
    ca, ce = bytes.fromhex(v["ct_anml_hex"]), bytes.fromhex(v["ct_erth_hex"])
    assert hx(privacy.registration_binding(cid, idc_, a, ca, e, ce, 0)) == v["none"]
    aff = privacy.affiliate_field(v["affiliate_handle"])
    assert hx(aff) == v["affiliate_field"]
    assert hx(privacy.registration_binding(cid, idc_, a, ca, e, ce, aff)) == v["affiliate"]
    # The affiliate field covers the handle (only: the chain makes the note).
    assert privacy.affiliate_field("amy-3") != aff
    # The binding covers each ciphertext.
    assert privacy.registration_binding(cid, idc_, a, ca[:-1] + b"\x00", e, ce, 0) != int(v["none"], 16)
    assert privacy.registration_binding(cid, idc_, a, ca, e, ce[:-1] + b"\x00", 0) != int(v["none"], 16)
    # And the chain id (audit round 6, B6-4).
    assert hx(privacy.registration_binding("earth-2", idc_, a, ca, e, ce, 0)) == v["other_chain"] != v["none"]


def test_referral_opening_matches_go():
    v = VEC["referral_opening"]
    rho, rcm = privacy.referral_opening(int(v["nullifier"], 16), v["leaf_index"])
    assert (hx(rho), hx(rcm)) == (v["rho"], v["rcm"])
    assert hx(privacy.pc(int(v["owner_pk"], 16), rho, rcm)) == v["pc"]
    # Unique per leaf index.
    assert privacy.referral_opening(int(v["nullifier"], 16), v["leaf_index"] + 1)[0] != rho


def test_registration_binding_pinned_to_chain_test():
    # chain zk/privacy TestRegistrationBindingPinned (f4a217c, chain id bound).
    want = "148b3513a501b6ff9c02314f355cb83fb544e22b2a9df79552fe49c944424159"
    assert VEC["registration_binding"]["pinned"] == want
    assert hx(privacy.registration_binding("earth-1", 1, 2, b"anml", 3, b"erth", 0)) == want


def test_stake_nullifier_tree_matches_go():
    """zk/indexed: nf_leaf, the sentinel-only root, and the root after each insert."""
    assert hx(privacy.nf_leaf(1, 2, 3)) == VEC["nf_leaf_1_2_3"]
    # ORCHARD_DESIGN.md section 15's golden values.
    assert VEC["nf_leaf_1_2_3"] == "0cdc3a81748c6389efaa3a6c29b7f4609a8e9f860230b70413e8bef512978276"
    assert hx(indexed.EMPTY_ROOT) == VEC["nf_empty_root"]
    t = indexed.IndexedTree()
    assert (t.size, hx(t.root())) == (0, VEC["nf_empty_root"])
    for i, (v, want) in enumerate(zip(VEC["nf_values"], VEC["nf_roots"])):
        assert t.insert(int(v, 16)) == i + 1
        assert hx(t.root()) == want, f"root after insert {i + 1}"
    assert t.size == len(VEC["nf_values"]) + 1


def test_stake_nullifier_tree_refuses_zero_repeats_and_non_canonical():
    import pytest

    t = indexed.IndexedTree()
    t.insert(5)
    for bad in (0, 5, poseidon2.P):
        with pytest.raises(ValueError):
            t.insert(bad)


def test_debt_tags_match_the_circuits():
    # zk/privacy/privacy.go: TAG_SLABEL "earth.slabel", TAG_DEBTL "earth.debtl".
    assert privacy.TAG_SLABEL == int.from_bytes(b"earth.slabel", "big")
    assert privacy.TAG_DEBTL == int.from_bytes(b"earth.debtl", "big")


def test_debt_tree_matches_go():
    # zk/debt TestNoirParity pins DebtLeaf(1, 2, 3, 4) and EmptyRoot.
    assert hx(privacy.debt_leaf(1, 2, 3, 4)) == VEC["debt_leaf_1_2_3_4"] == \
        "0b28cc858d976ddad0ede75ca9538f9b5ab36538964f6e241b8e89be2711e82a"
    assert hx(debt.EMPTY_ROOT) == VEC["debt_empty_root"] == \
        "0cea3d3e26cd2710109d7cbff5bf48570ba54332f812d538893f0958007f6903"
    t = debt.DebtTree()
    assert t.size == 0 and t.root() == debt.EMPTY_ROOT
    for key, retained, idx, root in VEC["debt_sets"]:
        assert t.set(int(key, 16), int(retained)) == int(idx)
        assert hx(t.root()) == root
    # The last set rewrote the first row: no leaf appended.
    assert t.size == 7


def test_debt_tree_refuses_bad_rows():
    t = debt.DebtTree()
    for key, retained in ((0, 1), (debt.P, 1), (1, -1), (1, 1 << 64)):
        with pytest.raises(ValueError):
            t.set(key, retained)
