// Scenarios recorded only by bin/record-chain-fixtures.sh (copied into an
// exported copy of the chain, never the chain repo), for chain behaviour no
// chain test drives entirely in blocks. The chain's own tests fund pools and
// make moves outside FinalizeBlock (auditFundPool, auditDelegate,
// fakeRedelegate): state no node's block_results describe, so an indexer
// fed their blocks rightly halts. Every shielded write here is a tx in a
// block. Their proofs are cached in bin/chainrec/proofs (proven with
// EARTH_CIRCUITS when missing).

package app

import (
	"strconv"
	"testing"
	"time"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	allocationkeeper "github.com/earth-network/earth/x/allocation/keeper"
	allocationtypes "github.com/earth-network/earth/x/allocation/types"
	sstypes "github.com/earth-network/earth/x/shieldedstaking/types"
)

// TestRecordRedelegateSlashDebt: TestRedelegateSlashDebt in blocks only. A
// first delegation (a padding spend), two private redelegations A -> B after
// an infraction of A (the first pads its credit lane, the second makes a
// second labelled note at B), the evidence (two debt rows, one slash_debt), a
// top-up of the first labelled note (keeps its label), the window closing,
// the label cleared at its retained value, and the cleared note undelegated.
func TestRecordRedelegateSlashDebt(t *testing.T) {
	e := initStakeEnv(t)
	vA, _ := e.createValidator(1000 * ssErth)
	vB, _ := e.createValidator(1000 * ssErth)
	e.next(5 * time.Second)
	e.shield(uint64(5_000 * ssErth))
	for range 6 {
		e.shield(uint64(100 * ssErth))
	}
	n := e.delegate(vA, uint64(2_000*ssErth))
	e.days(1)
	e.next(time.Hour)

	e.next(5 * time.Second)
	infraction := e.height
	e.next(5 * time.Second)
	e.next(5 * time.Second)
	b1, _ := e.redelegate(vA, vB, n, uint64(1_000*ssErth))
	change := e.unspentStake(sstypes.DerthDenom(e.valoper(vA)))
	require.NotNil(t, change)
	b2, _ := e.redelegate(vA, vB, change, uint64(500*ssErth))
	require.NotEqual(t, b1.moveKey, b2.moveKey)

	res := e.doubleSign(vA, infraction)
	require.Len(t, eventsOf(res.Events, sstypes.EventTypeDebtRow), 2)
	require.Len(t, eventsOf(res.Events, sstypes.EventTypeMoveSlashed), 2)
	require.Len(t, eventsOf(res.Events, sstypes.EventTypeSlashDebt), 1)
	e.invariants()

	top := e.delegate(vB, uint64(200*ssErth))
	require.Equal(t, b1.moveKey, top.moveKey)
	require.Equal(t, b1.exposed, top.exposed)

	e.days(22)
	cleared := e.restake([]*snote{top}, true)
	require.False(t, cleared.labelled())
	e.undelegate(vB, cleared, cleared.amount)
	e.invariants()
}

// TestRecordGroundworksLease: Groundworks leases in blocks (chain 654f698,
// 653e240; votes by stake note since v1.2.0, no stake vote lease since
// v1.3.0), at the shortest operator lease (one day). A stake note voting a
// split (MsgRestake), re-cast by a restake voting the same split halfway
// through what was its lease, standing past it (a stake vote ends with its
// vintage, not a lease: split_expires_at is 0); and an operator's
// MsgSetAllocations vote lapsing at its lease end (x/allocation
// split_lapsed).
func TestRecordGroundworksLease(t *testing.T) {
	e := initStakeEnv(t)
	vB, opKey := e.createValidator(1000 * ssErth)
	e.next(5 * time.Second)
	e.shield(uint64(3_000 * ssErth))
	for range 4 {
		e.shield(uint64(100 * ssErth))
	}
	gw := allocationtypes.STREAM_ID_GROUNDWORKS
	ak := e.app.AllocationKeeper
	gov := authtypes.NewModuleAddress("gov")
	require.NoError(t, e.app.BankKeeper.SendCoins(e.ctx(), e.userAddr(), gov, sdk.NewCoins(sdk.NewInt64Coin("uerth", 10*ssErth))))
	_, err := allocationkeeper.NewMsgServerImpl(ak).AddAddressOption(e.ctx(), &allocationtypes.MsgAddAddressOption{
		Submitter: e.bech(gov), Stream: gw, Description: "a public good", Recipient: e.bech(e.userAddr()),
	})
	require.NoError(t, err)
	params, err := ak.Params.Get(e.ctx())
	require.NoError(t, err)
	params.GroundworksLeaseSeconds = allocationtypes.MinGroundworksLeaseSeconds
	require.NoError(t, ak.Params.Set(e.ctx(), params))
	lease := int64(allocationtypes.MinGroundworksLeaseSeconds)
	e.next(5 * time.Second)
	opt := []allocationtypes.AllocationWeight{{OptionId: 1, Percent: 100}}
	votes := func() []sstypes.GroundworksVote {
		var out []sstypes.GroundworksVote
		require.NoError(t, e.app.ShieldedStakingKeeper.GwVotes.Walk(e.ctx(), nil, func(_ uint64, v sstypes.GroundworksVote) (bool, error) {
			out = append(out, v)
			return false, nil
		}))
		return out
	}

	dn := e.delegate(vB, uint64(1_000*ssErth))
	e.days(2)
	voting := e.restakeVote([]*snote{dn}, false, opt)
	require.Len(t, votes(), 1)
	require.Zero(t, votes()[0].SplitExpiresAt, "a stake vote has no lease (v1.3.0)")
	require.Equal(t, e.month(), votes()[0].Vintage)
	exp := e.now.Unix() + lease // where a lease would have ended

	// Re-cast halfway: the note respent onto itself with the same split.
	e.next(12 * time.Hour)
	e.restakeVote([]*snote{voting}, false, opt)
	require.Len(t, votes(), 1)
	require.Zero(t, votes()[0].SplitExpiresAt)
	renewed := e.now.Unix() + lease

	// The operator votes its self-bond.
	op := sdk.AccAddress(vB)
	res := e.run(e.signedTx(opKey, 500_000, 5_000, &allocationtypes.MsgSetAllocations{
		Creator: e.bech(op), Stream: gw, Percentages: opt,
	}))
	require.Equal(t, uint32(0), res.Code, res.Log)
	voter, err := ak.Voters.Get(e.ctx(), collections.Join(uint32(gw), []byte(op)))
	require.NoError(t, err)
	opExp := voter.ExpiresAt
	require.Equal(t, e.now.Unix()+lease, opExp)

	// Past both would-be lease ends the stake vote stands; the operator's
	// vote lapses at its lease end.
	e.atUnix(exp + 60)
	require.Len(t, votes(), 1)
	e.next(time.Duration(renewed-e.now.Unix()) * time.Second)
	require.Len(t, votes(), 1)
	fbk := e.next(time.Duration(opExp-e.now.Unix()+5) * time.Second)
	require.Len(t, votes(), 1)
	require.Len(t, eventsOf(fbk.Events, "split_lapsed"), 1)
	_, err = ak.Voters.Get(e.ctx(), collections.Join(uint32(gw), []byte(op)))
	require.ErrorIs(t, err, collections.ErrNotFound)
	e.invariants()
}

// TestRecordStakeVintages: stake vintages (v1.3.0) in blocks. A January
// delegation on the base vintage's unsuffixed derth/<valoper>; in February
// most of it checks in (MsgCheckIn: the change stays in January, the credit
// is an unlabelled derth/<valoper>/<YYYYMM> note) and is restaked naming
// its month (a non-zero msg vintage); the January change votes a
// Groundworks split. At January's retirement (BeginBlock) its supply leaves
// the book as a held undelegation and its vote is swept (action
// "retired"); the change note, still on the unsuffixed asset a pre-v1.3.0
// wallet built it with, withdraws whole (MsgUndelegate, vintage 0) and its
// share is paid at the record's maturity. February stays live throughout.
func TestRecordStakeVintages(t *testing.T) {
	e := initStakeEnv(t)
	vB, _ := e.createValidator(1000 * ssErth)
	e.next(5 * time.Second)
	e.shield(uint64(5_000 * ssErth))
	for range 6 {
		e.shield(uint64(100 * ssErth))
	}
	gw := allocationtypes.STREAM_ID_GROUNDWORKS
	gov := authtypes.NewModuleAddress("gov")
	require.NoError(t, e.app.BankKeeper.SendCoins(e.ctx(), e.userAddr(), gov, sdk.NewCoins(sdk.NewInt64Coin("uerth", 10*ssErth))))
	_, err := allocationkeeper.NewMsgServerImpl(e.app.AllocationKeeper).AddAddressOption(e.ctx(), &allocationtypes.MsgAddAddressOption{
		Submitter: e.bech(gov), Stream: gw, Description: "a public good", Recipient: e.bech(e.userAddr()),
	})
	require.NoError(t, err)
	opt := []allocationtypes.AllocationWeight{{OptionId: 1, Percent: 100}}
	e.next(5 * time.Second)

	jan := e.month()
	dn := e.delegate(vB, uint64(2_000*ssErth))
	require.Equal(t, sstypes.DerthDenom(e.valoper(vB)), dn.denom, "the base vintage: the unsuffixed denom")
	e.days(1)

	// February: check 1,500 derth in.
	feb := sstypes.AddMonths(jan, 1)
	e.toTime(sstypes.VintageStart(feb).Add(time.Hour))
	vc, err := e.app.ShieldedStakingKeeper.VintageContext(e.ctx())
	require.NoError(t, err)
	require.Equal(t, feb, vc.Current)
	febDenom := sstypes.VintageDenom(e.valoper(vB), feb, vc.Base)
	amount := uint64(1_500 * ssErth)
	p := e.feeOnly()
	change := e.freshStake(dn.denom, dn.amount-amount)
	sp := e.stake(&stakePlan{denom: dn.denom, ins: []*snote{dn}, vOut: amount, out: change,
		credit: &creditLane{denom: febDenom, vIn: amount}})
	m := &sstypes.MsgCheckIn{Bundle: p.b, Validator: e.valoper(vB), FromVintage: jan, Amount: amount, Stake: sp.proof}
	e.prove(m, p)
	e.proveStake(m, sp)
	res := e.run(e.privateTx(m))
	require.Equal(t, uint32(0), res.Code, res.Log)
	e.settle(p)
	e.settleStake(sp)
	require.Len(t, eventsOf(res.Events, sstypes.EventTypeCheckIn), 1)
	require.Equal(t, febDenom, sp.credit.out.denom)
	e.next(5 * time.Second)

	// The February note restaked naming its month; the January change votes.
	febNote := e.restake([]*snote{sp.credit.out}, false)
	require.Equal(t, febDenom, febNote.denom)
	janNote := e.restakeVote([]*snote{change}, false, opt)
	e.invariants()

	// January retires: its supply is booked as a held undelegation, its
	// vote swept.
	e.toTime(sstypes.VintageRetiresAt(jan).Add(time.Minute))
	rv, ok := e.retiredVintage(vB, jan)
	require.True(t, ok)
	require.Equal(t, math.NewIntFromUint64(janNote.amount), rv.Supply)
	require.True(t, e.vsupply(vB, feb).IsPositive(), "February is live")
	e.next(5 * time.Second)

	// The January note withdraws whole, on its unsuffixed asset.
	um, up, usp, out := e.undelegateMsg(vB, janNote, janNote.amount)
	require.Nil(t, usp.out, "the whole note: a zero note out")
	res = e.run(e.privateTx(um))
	require.Equal(t, uint32(0), res.Code, res.Log)
	e.settle(up)
	e.settleStake(usp)
	ev := eventsOf(res.Events, sstypes.EventTypeRetiredWithdrawal)
	require.Len(t, ev, 1)
	require.Equal(t, rv.Value.String(), ev[0]["value"])
	id, err := strconv.ParseUint(ev[0]["payout_id"], 10, 64)
	require.NoError(t, err)
	e.invariants()

	e.days(1)
	e.days(22)
	got := e.payout(&unbonding{id: id, epoch: rv.Epoch, value: rv.Value.Uint64(), out: out})
	require.NotNil(t, got)
	e.invariants()
}
