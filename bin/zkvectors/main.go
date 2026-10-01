// Command zkvectors prints test vectors from the chain's own zk packages, for
// tests/fixtures/privacy/zk_vectors.json. Run it through bin/zk-vectors.sh,
// which points a throwaway module at a chain checkout.

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	out["identity_leaf_DE"] = hx(privacy.IdentityLeaf(privacy.IDC(u(11)), u(12), privacy.CountryField("DE"), 1700000000))

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
		l := privacy.IdentityLeaf(privacy.IDC(u(500+i)), u(600+i), privacy.CountryField("UT"), 1700000000+i)
		it.Append(l)
		leaves = append(leaves, hx(l))
	}
	r3, _ := it.Root()
	it.Update(1, fr.Element{})
	rz, _ := it.Root()
	out["identity_leaves"] = leaves
	out["identity_root_3"] = hx(r3)
	out["identity_root_zeroed1"] = hx(rz)
	json.NewEncoder(os.Stdout).Encode(out)
}
