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

	"github.com/stretchr/testify/require"

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
