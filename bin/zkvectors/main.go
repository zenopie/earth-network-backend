// Command zkvectors prints test vectors from the chain's own zk packages, for
// tests/fixtures/privacy/zk_vectors.json. Run it through bin/zk-vectors.sh,
// which points a throwaway module at a chain checkout.

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
	personhoodtypes "github.com/earth-network/earth/x/personhood/types"
	shieldedtypes "github.com/earth-network/earth/x/shielded/types"
	"github.com/earth-network/earth/zk/indexed"
	"github.com/earth-network/earth/zk/merkle"
	"github.com/earth-network/earth/zk/poseidon2"
	"github.com/earth-network/earth/zk/privacy"
)

func hx(e fr.Element) string { return hex.EncodeToString(privacy.FieldBytes(e)) }
func u(v uint64) fr.Element  { return privacy.U64(v) }

func main() {
	out := map[string]any{}
	out["hash_1_2"] = hx(poseidon2.Hash([]fr.Element{u(1), u(2)}))
	out["hash_5"] = hx(poseidon2.Hash([]fr.Element{u(1), u(2), u(3), u(4), u(5)}))
	out["zero32"] = hx(merkle.Zero[merkle.Depth])
	out["asset_uerth"] = hx(privacy.AssetID("uerth"))
	out["asset_uanml"] = hx(privacy.AssetID("uanml"))
	long := "derth/earthvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	out["asset_long"] = map[string]string{"denom": long, "id": hx(privacy.AssetID(long))}
	pc := privacy.PC(privacy.OwnerPK(u(42)), u(7), u(9))
	out["pc"] = hx(pc)
	out["cm_uerth_100000"] = hx(privacy.CM(privacy.AssetID("uerth"), 100000, pc))
	out["identity_leaf_DE"] = hx(privacy.IdentityLeaf(privacy.IDC(u(11)), u(12), privacy.CountryField("DE"), 1700000000, 0))
	out["identity_leaf_DE_pred"] = hx(privacy.IdentityLeaf(privacy.IDC(u(11)), u(12), privacy.CountryField("DE"), 1700000000, 1690000000))

	// note tree: 5 cms derived deterministically
	nt := merkle.NewMem()
	var cms []string
	var roots []string
	for i := uint64(0); i < 5; i++ {
		cm := privacy.CM(privacy.AssetID("uerth"), 1000+i, privacy.PC(u(100+i), u(200+i), u(300+i)))
		nt.Append(cm)
		cms = append(cms, hx(cm))
		r, _ := nt.Root()
		roots = append(roots, hx(r))
	}
	out["note_cms"] = cms
	out["note_roots"] = roots

	// identity tree: 3 leaves, then zero index 1
	it := merkle.NewMem()
	var leaves []string
	for i := uint64(0); i < 3; i++ {
		l := privacy.IdentityLeaf(privacy.IDC(u(500+i)), u(600+i), privacy.CountryField("UT"), 1700000000+i, i*1000)
		it.Append(l)
		leaves = append(leaves, hx(l))
	}
	r3, _ := it.Root()
	it.Update(1, fr.Element{})
	rz, _ := it.Root()
	out["identity_leaves"] = leaves
	out["identity_root_3"] = hx(r3)
	out["identity_root_zeroed1"] = hx(rz)
	// stake tree: privacy.StakePC/StakeCM leaves in a zk/merkle tree, as
	// x/shieldedstaking's stake tree holds them.
	spc := privacy.StakePC(privacy.OwnerPK(u(42)), u(7), u(9))
	out["stake_pc"] = hx(spc)
	out["stake_cm_derth"] = map[string]string{"denom": long, "amount": "250000", "cm": hx(privacy.StakeCM(privacy.AssetID(long), 250000, spc))}
	st := merkle.NewMem()
	var scms, sroots []string
	for i := uint64(0); i < 4; i++ {
		cm := privacy.StakeCM(privacy.AssetID(long), 10+i, privacy.StakePC(u(700+i), u(800+i), u(900+i)))
		st.Append(cm)
		scms = append(scms, hx(cm))
		r, _ := st.Root()
		sroots = append(sroots, hx(r))
	}
	out["stake_cms"] = scms
	out["stake_roots"] = sroots

	// The stake nullifier tree (zk/indexed): NFLeaf, the empty (sentinel
	// only) root, and the root after each insert of values in an order that
	// is neither sorted nor reversed, small and full-width, so a low leaf in
	// the middle, at the sentinel and at the largest value are all exercised.
	out["nf_leaf_1_2_3"] = hx(privacy.NFLeaf(u(1), u(2), 3))
	out["nf_empty_root"] = hx(indexed.EmptyRoot)
	nft := indexed.NewMem()
	var nfs, nfroots []string
	for i := uint64(0); i < 9; i++ {
		var v fr.Element
		switch i % 3 {
		case 0:
			v = privacy.H(u(1000 + i))
		case 1:
			v = u(50 - i)
		default:
			v = u(1 << (40 + i))
		}
		idx, err := nft.Insert(v)
		if err != nil || idx != i+1 {
			panic("indexed insert")
		}
		nfs = append(nfs, hx(v))
		r, _ := nft.Root()
		nfroots = append(nfroots, hx(r))
	}
	out["nf_values"] = nfs
	out["nf_roots"] = nfroots

	// The registration binding: the passport proof's address input, as
	// personhood's MsgRegister.Binding computes it (affiliate 0 for none, else
	// AffiliateField(affiliate_handle, affiliate_pc, affiliate_ciphertext)).
	// The gas backend checks it before gas-check.
	ctA, ctE, ctR := make([]byte, 177), make([]byte, 177), make([]byte, 177)
	for i := range ctA {
		ctA[i], ctE[i], ctR[i] = byte(i), byte(255-i), byte(i*7)
	}
	affPC := privacy.PC(privacy.OwnerPK(u(77)), u(78), u(79))
	reg := personhoodtypes.MsgRegister{AffiliateHandle: "amy-2", AffiliatePc: privacy.FieldBytes(affPC), AffiliateCiphertext: ctR}
	affMsg, err := reg.AffiliateField()
	if err != nil {
		panic(err)
	}
	aff := privacy.AffiliateField("amy-2", affPC, ctR)
	if aff != affMsg {
		panic("AffiliateField differs from MsgRegister.AffiliateField")
	}
	out["registration_binding"] = map[string]string{
		"idc": hx(u(11)), "pc_anml": hx(u(12)), "pc_erth": hx(u(13)),
		"ct_anml_hex": hex.EncodeToString(ctA), "ct_erth_hex": hex.EncodeToString(ctE),
		"none":             hx(privacy.RegistrationBinding(u(11), u(12), ctA, u(13), ctE, fr.Element{})),
		"affiliate_handle": "amy-2",
		"affiliate_pc":     hx(affPC),
		"affiliate_ct_hex": hex.EncodeToString(ctR),
		"affiliate_field":  hx(aff),
		"affiliate":        hx(privacy.RegistrationBinding(u(11), u(12), ctA, u(13), ctE, aff)),
		// TestRegistrationBindingPinned's own inputs and value.
		"pinned": hx(privacy.RegistrationBinding(u(1), u(2), []byte("anml"), u(3), []byte("erth"), fr.Element{})),
	}

	// MsgShield as the chain encodes it, for the backend's hand-built proto.
	shield := shieldedtypes.MsgShield{
		Sender:     "earth1qqqsyqcyq5rqwzqfpg9scrgwpugpzysncc2uls",
		Amount:     sdk.NewCoin("uerth", math.NewInt(100000)),
		Pc:         privacy.FieldBytes(pc),
		Ciphertext: ctA, // exactly 177 bytes, as ValidateBasic requires
	}
	if err := shield.ValidateBasic(); err != nil {
		panic(err)
	}
	bz, err := shield.Marshal()
	if err != nil {
		panic(err)
	}
	out["msg_shield"] = map[string]string{"sender": shield.Sender, "pc": hx(pc), "ciphertext_hex": hex.EncodeToString(shield.Ciphertext), "encoded": hex.EncodeToString(bz)}
	json.NewEncoder(os.Stdout).Encode(out)
}
