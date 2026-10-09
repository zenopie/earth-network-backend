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
	"testing"
	"time"

	"cosmossdk.io/collections"

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

// TestRecordGroundworksLease: the Groundworks vote lease (chain 654f698,
// 653e240; votes by stake note since v1.2.0) in blocks, at the shortest
// lease (one day). A stake note voting a split (MsgRestake), renewed by a
// restake voting the same split halfway through its lease, standing past
// its first lease end and lapsing at its renewed one (the vote deleted, in
// BeginBlock); and an operator's MsgSetAllocations vote lapsing the same way
// (x/allocation split_lapsed).
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
	exp := votes()[0].SplitExpiresAt
	require.Equal(t, e.now.Unix()+lease, exp)

	// Renewed halfway: the note respent onto itself with the same split.
	e.next(12 * time.Hour)
	e.restakeVote([]*snote{voting}, false, opt)
	require.Len(t, votes(), 1)
	renewed := votes()[0].SplitExpiresAt
	require.Equal(t, e.now.Unix()+lease, renewed)

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

	// Past the first lease end the renewed vote stands.
	e.atUnix(exp + 60)
	require.Len(t, votes(), 1)
	// At the renewed end it lapses (BeginBlock), then the operator's vote.
	e.next(time.Duration(renewed-e.now.Unix()) * time.Second)
	require.Empty(t, votes())
	fbk := e.next(time.Duration(opExp-e.now.Unix()+5) * time.Second)
	require.Len(t, eventsOf(fbk.Events, "split_lapsed"), 1)
	_, err = ak.Voters.Get(e.ctx(), collections.Join(uint32(gw), []byte(op)))
	require.ErrorIs(t, err, collections.ErrNotFound)
	e.invariants()
}
