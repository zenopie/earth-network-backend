// Command zkvectors prints test vectors from the chain's own zk packages, for
// tests/fixtures/privacy/zk_vectors.json. Run it through bin/zk-vectors.sh,
// which points a throwaway module at a chain checkout.

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
	personhoodtypes "github.com/earth-network/earth/x/personhood/types"
	shieldedtypes "github.com/earth-network/earth/x/shielded/types"
	sstypes "github.com/earth-network/earth/x/shieldedstaking/types"
	"github.com/earth-network/earth/zk/debt"
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
	out["succession_leaf"] = hx(privacy.SuccessionLeaf(privacy.IDC(u(11)), privacy.IDC(u(21))))

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
	// StakeCM carries the slash label (chain dff3a9b): 0 for an unlabelled
	// note, else StakeLabel(move_key, move_time, exposed).
	out["stake_cm_derth"] = map[string]string{"denom": long, "amount": "250000", "cm": hx(privacy.StakeCM(privacy.AssetID(long), 250000, spc, fr.Element{}))}
	label := privacy.StakeLabel(u(0x4d4b), 1000, 200)
	out["stake_label"] = map[string]string{"move_key": hx(u(0x4d4b)), "move_time": "1000", "exposed": "200", "label": hx(label)}
	out["stake_cm_labelled"] = map[string]string{"denom": long, "amount": "250000", "cm": hx(privacy.StakeCM(privacy.AssetID(long), 250000, spc, label))}
	st := merkle.NewMem()
	var scms, sroots []string
	for i := uint64(0); i < 4; i++ {
		cm := privacy.StakeCM(privacy.AssetID(long), 10+i, privacy.StakePC(u(700+i), u(800+i), u(900+i)), fr.Element{})
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

	// The slash debt tree (zk/debt): DebtLeaf, the empty root, and the root
	// after each Set of a sequence of rows: new keys in an order neither
	// sorted nor reversed, then a row rewritten (its retained falls).
	out["debt_leaf_1_2_3_4"] = hx(privacy.DebtLeaf(u(1), u(2), 3, 4))
	out["debt_empty_root"] = hx(debt.EmptyRoot)
	dt := debt.NewMem()
	var dsets [][]string
	for i := uint64(0); i < 7; i++ {
		var k fr.Element
		retained := 1000 * (i + 1)
		switch {
		case i == 6:
			k, retained = privacy.H(u(2000)), 1 // rewrites the first row
		case i%3 == 0:
			k = privacy.H(u(2000 + i))
		case i%3 == 1:
			k = u(90 - i)
		default:
			k = u(1 << (50 + i))
		}
		idx, err := dt.Set(k, retained)
		if err != nil {
			panic(err)
		}
		r, _ := dt.Root()
		dsets = append(dsets, []string{hx(k), strconv.FormatUint(retained, 10), strconv.FormatUint(idx, 10), hx(r)})
	}
	out["debt_sets"] = dsets

	// The registration binding: the passport proof's address input, as
	// personhood's MsgRegister.Binding computes it (affiliate 0 for none, else
	// AffiliateField(affiliate_handle) = H("earth.affiliate", Bytes(handle))).
	// The gas backend checks it before gas-check.
	ctA, ctE := make([]byte, 177), make([]byte, 177)
	for i := range ctA {
		ctA[i], ctE[i] = byte(i), byte(255-i)
	}
	reg := personhoodtypes.MsgRegister{AffiliateHandle: "amy-2"}
	affMsg, err := reg.AffiliateField()
	if err != nil {
		panic(err)
	}
	aff := privacy.AffiliateField("amy-2")
	if aff != affMsg {
		panic("AffiliateField differs from MsgRegister.AffiliateField")
	}
	// The binding covers the chain id (audit round 6, B6-4).
	const chainID = "earth-1"
	out["registration_binding"] = map[string]string{
		"chain_id": chainID,
		"idc":      hx(u(11)), "pc_anml": hx(u(12)), "pc_erth": hx(u(13)),
		"ct_anml_hex": hex.EncodeToString(ctA), "ct_erth_hex": hex.EncodeToString(ctE),
		"none":             hx(privacy.RegistrationBinding(chainID, u(11), u(12), ctA, u(13), ctE, fr.Element{})),
		"affiliate_handle": "amy-2",
		"affiliate_field":  hx(aff),
		"affiliate":        hx(privacy.RegistrationBinding(chainID, u(11), u(12), ctA, u(13), ctE, aff)),
		"other_chain":      hx(privacy.RegistrationBinding("earth-2", u(11), u(12), ctA, u(13), ctE, fr.Element{})),
		// TestRegistrationBindingPinned's own inputs and value.
		"pinned": hx(privacy.RegistrationBinding(chainID, u(1), u(2), []byte("anml"), u(3), []byte("erth"), fr.Element{})),
	}

	// The referral note's opening (the chain mints it; its shielded_mint
	// event carries owner_pk, rho, rcm): a wallet recomputes pc and cm.
	refOwner := privacy.OwnerPK(u(77))
	refRho, refRcm := privacy.ReferralOpening(u(88), 5)
	refPC := privacy.PC(refOwner, refRho, refRcm)
	out["referral_opening"] = map[string]any{
		"nullifier": hx(u(88)), "leaf_index": 5, "owner_pk": hx(refOwner),
		"rho": hx(refRho), "rcm": hx(refRcm), "pc": hx(refPC),
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

	// The Handles query's wire shape (x/personhood QueryHandlesRequest /
	// QueryHandlesResponse), for services/privacy/handles: a request with a
	// start and a limit, and a page with an entry of each status and a next.
	hreq := personhoodtypes.QueryHandlesRequest{Start: "amy", Limit: 1000}
	hreqBz, err := hreq.Marshal()
	if err != nil {
		panic(err)
	}
	var ek [32]byte
	for i := range ek {
		ek[i] = byte(i + 1)
	}
	addr := privacy.ShieldedAddress{OwnerPK: privacy.OwnerPK(u(42)), EKPub: ek}.Encode()
	hres := personhoodtypes.QueryHandlesResponse{Handles: []personhoodtypes.HandleEntry{
		// owner (field 6): "" for a handle never claimed, else the
		// handle-scope nullifier as 64 lowercase hex.
		{Handle: "a-1", Address: addr, Status: "free", ExpiresAt: 1600000000, RenewalUntil: 1602592000},
		{Handle: "bob", Address: addr, Status: "renewal", ExpiresAt: 1700000000, RenewalUntil: 1702592000, Owner: hx(u(5))},
		{Handle: "zed-99", Address: addr, Status: "live", ExpiresAt: 1800000000, RenewalUntil: 1802592000, Owner: hx(u(6))},
	}, Next: "zed-99"}
	hresBz, err := hres.Marshal()
	if err != nil {
		panic(err)
	}
	out["handles_query"] = map[string]any{
		"request_start": hreq.Start, "request_limit": hreq.Limit, "request": hex.EncodeToString(hreqBz),
		"response": hex.EncodeToString(hresBz), "address": addr, "next": hres.Next, "entries": hres.Handles,
	}
	// Stake vintages (v1.3.0, x/shieldedstaking/types/vintage.go): the
	// denom of a (validator, vintage), ParseDerthDenom over good and bad
	// spellings, months, liveness and retirement times, and the stake
	// commitment of a suffixed note.
	const val = "earthvaloper1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	var denoms [][]any
	for _, c := range [][2]uint32{{202610, 202610}, {202611, 202610}, {202609, 202610}, {210001, 202610}, {202610, 202501}} {
		denoms = append(denoms, []any{val, c[0], c[1], sstypes.VintageDenom(val, c[0], c[1])})
	}
	var parses [][]any
	for _, d := range []string{
		"derth/" + val, "derth/" + val + "/202610", "derth/" + val + "/200001", "derth/" + val + "/999912",
		"derth/" + val + "/202613", "derth/" + val + "/202600", "derth/" + val + "/199912", "derth/" + val + "/20261",
		"derth/" + val + "/2026100", "derth/" + val + "/+20261", "derth/" + val + "/2026/1", "derth/" + val + "/",
		"derth/", "derth", "derth//202610", "uerth", "xderth/" + val, "derth/" + val + "/0x2026",
	} {
		v, m, ok := sstypes.ParseDerthDenom(d)
		parses = append(parses, []any{d, v, m, ok})
	}
	var months [][]any
	for _, ts := range []int64{1798761599, 1798761600, 1801439999, 1801440000, 1830297600, 1735689600, 951782400} {
		m := sstypes.MonthOf(time.Unix(ts, 0))
		months = append(months, []any{ts, m, sstypes.VintageStart(m).Unix(), sstypes.VintageRetiresAt(m).Unix(), sstypes.OldestLiveVintage(m)})
	}
	var live [][]any
	for _, c := range [][2]uint32{{202610, 202610}, {202510, 202610}, {202509, 202610}, {202611, 202610}, {202512, 202612}, {202511, 202612}, {202601, 202701}, {202512, 202701}} {
		live = append(live, []any{c[0], c[1], sstypes.VintageLive(c[0], c[1]), sstypes.VintageRetired(c[0], c[1])})
	}
	// The month-boundary grace (NewVintageCtx, CheckCredit): a credit may
	// name the previous month during the current one's first
	// VintageGraceSeconds.
	var grace [][]any
	for _, ts := range []int64{1798761599, 1798761600, 1798765199, 1798765200, 1801439999, 1801440000, 1801443599, 1801443600, 1830297600} {
		vc := sstypes.NewVintageCtx(202610, time.Unix(ts, 0))
		for _, m := range []uint32{vc.Current, sstypes.AddMonths(vc.Current, -1), sstypes.AddMonths(vc.Current, -2), sstypes.AddMonths(vc.Current, 1)} {
			grace = append(grace, []any{ts, vc.Current, vc.Grace, m, vc.CheckCredit(m) == nil})
		}
	}
	vden := sstypes.VintageDenom(val, 202611, 202610)
	out["vintages"] = map[string]any{
		"live_months": sstypes.LiveVintageMonths, "denoms": denoms, "parse": parses, "months": months, "live": live,
		"grace_seconds": sstypes.VintageGraceSeconds, "grace": grace,
		"asset": map[string]string{"denom": vden, "id": hx(privacy.AssetID(vden))},
		"stake_cm": map[string]string{"denom": vden, "amount": "250000", "cm": hx(privacy.StakeCM(privacy.AssetID(vden), 250000, spc, fr.Element{}))},
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
