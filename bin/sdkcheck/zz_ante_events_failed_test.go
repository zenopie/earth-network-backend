// The SDK behaviour the privacy indexer depends on, checked in the SDK's own
// baseapp test harness: when a tx's msg fails after its ante succeeded, the
// ante's writes persist and its events are in the failed tx's result; when
// the ante fails, neither. Not part of this repo's build. To run:
//
//   cp -R "$(go env GOMODCACHE)/github.com/cosmos/cosmos-sdk@v0.53.6" /tmp/sdk && chmod -R u+w /tmp/sdk
//   cp bin/sdkcheck/zz_ante_events_failed_test.go /tmp/sdk/baseapp/
//   cd /tmp/sdk && GOFLAGS=-mod=mod go test ./baseapp -run TestZZ_AnteEventsOnFailedMsg -v
//
// Last run 2026-09-30 against v0.53.6 (the chain's): PASS
//   failed-msg tx: code=1 events=[{ante_handler [{update_counter 0 true}]}]
//   failed-ante tx: code=4 events=[]

package baseapp_test

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/baseapp"
	baseapptestutil "github.com/cosmos/cosmos-sdk/baseapp/testutil"
)

// A msg handler failure after a successful ante: are the ante's events in the
// ExecTxResult, and did the ante's writes persist?
func TestZZ_AnteEventsOnFailedMsg(t *testing.T) {
	anteKey := []byte("ante-key")
	anteOpt := func(bapp *baseapp.BaseApp) { bapp.SetAnteHandler(anteHandlerTxTest(t, capKey1, anteKey)) }
	suite := NewBaseAppSuite(t, anteOpt)
	_, err := suite.baseApp.InitChain(&abci.RequestInitChain{ConsensusParams: &cmtproto.ConsensusParams{}})
	require.NoError(t, err)
	baseapptestutil.RegisterCounterServer(suite.baseApp.MsgServiceRouter(), CounterServerImpl{t, capKey1, []byte("deliver-key")})

	tx := newTxCounter(t, suite.txConfig, 0, 0)
	tx = setFailOnHandler(suite.txConfig, tx, true)
	bz, err := suite.txConfig.TxEncoder()(tx)
	require.NoError(t, err)
	tx2 := newTxCounter(t, suite.txConfig, 1, 0)
	tx2 = setFailOnAnte(t, suite.txConfig, tx2, true)
	bz2, err := suite.txConfig.TxEncoder()(tx2)
	require.NoError(t, err)

	res, err := suite.baseApp.FinalizeBlock(&abci.RequestFinalizeBlock{Height: 1, Txs: [][]byte{bz, bz2}})
	require.NoError(t, err)
	r := res.TxResults[0]
	require.False(t, r.IsOK(), "msg handler must fail")
	t.Logf("failed-msg tx: code=%d events=%v", r.Code, r.Events)
	require.NotEmpty(t, r.Events)
	require.Equal(t, "ante_handler", r.Events[0].Type)
	r2 := res.TxResults[1]
	t.Logf("failed-ante tx: code=%d events=%v", r2.Code, r2.Events)
	require.Empty(t, r2.Events)
	_, err = suite.baseApp.Commit()
	require.NoError(t, err)

	// The ante's counter write persisted: the next tx's ante expects counter 1.
	ctx := getCheckStateCtx(suite.baseApp)
	require.Equal(t, int64(1), getIntFromStore(t, ctx.KVStore(capKey1), anteKey))
}
