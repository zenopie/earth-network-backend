// Recorder for tests/fixtures/privacy/*.json.gz. bin/record-chain-fixtures.sh
// copies this into an exported copy of the chain (never the chain repo) and
// hooks it into the app test envs' block helpers; each recorded test then
// writes every FinalizeBlock response, as CometBFT RPC block_results JSON,
// with the trees' sizes and roots after the block (note, identity, stake),
// to $RECORD_DIR.

package app

import (
	"encoding/json"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"

)

type recBlock struct {
	Height       int64           `json:"height"`
	Time         string          `json:"time"`
	Hash         string          `json:"hash"`
	BlockResults cmtjsonRaw      `json:"block_results"`
	NoteSize     uint64          `json:"note_tree_size"`
	NoteRoot     string          `json:"note_current_root"`
	NoteAnchor   string          `json:"note_latest_root"`
	IDSize       uint64          `json:"identity_tree_size"`
	IDRoot       string          `json:"identity_current_root"`
	IDAnchor     string          `json:"identity_latest_root"`
	StakeSize    uint64          `json:"stake_tree_size"`
	StakeAnchor  string          `json:"stake_latest_root"`
}

type cmtjsonRaw []byte

func (r cmtjsonRaw) MarshalJSON() ([]byte, error) { return r, nil }

var (
	recMu sync.Mutex
	recs  = map[string][]recBlock{}
	recCh = map[string]string{}
)

func recordBlock(t *testing.T, app *App, height int64, now time.Time, chainID string, res *abci.ResponseFinalizeBlock) {
	dir := os.Getenv("RECORD_DIR")
	if dir == "" {
		return
	}
	ctx := app.BaseApp.NewUncachedContext(false, cmtproto.Header{ChainID: chainID, Height: height, Time: now})
	nsize, _ := app.ShieldedKeeper.Size(ctx)
	nroot, _ := app.ShieldedKeeper.CurrentRoot(ctx)
	nanchor, _ := app.ShieldedKeeper.LatestRoot.Get(ctx)
	isize, _ := app.PersonhoodKeeper.IdentityTreeSize(ctx)
	iroot, _ := app.PersonhoodKeeper.CurrentIdentityRoot(ctx)
	ianchor, _ := app.PersonhoodKeeper.LatestIdentityRoot.Get(ctx)
	ssize, sanchor, _ := app.ShieldedStakingKeeper.StakeTreeState(ctx)
	br := &coretypes.ResultBlockResults{
		Height: height, TxsResults: res.TxResults, FinalizeBlockEvents: res.Events,
		ValidatorUpdates: res.ValidatorUpdates, ConsensusParamUpdates: res.ConsensusParamUpdates, AppHash: res.AppHash,
	}
	bz, err := cmtjson.Marshal(br)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(chainID + "/" + string(rune(height))))
	b := recBlock{
		Height: height, Time: now.UTC().Format(time.RFC3339Nano), Hash: strings.ToUpper(hex.EncodeToString(h[:])),
		BlockResults: bz, NoteSize: nsize, NoteRoot: hex.EncodeToString(nroot), NoteAnchor: hex.EncodeToString(nanchor),
		IDSize: isize, IDRoot: hex.EncodeToString(iroot), IDAnchor: hex.EncodeToString(ianchor),
		StakeSize: ssize, StakeAnchor: hex.EncodeToString(sanchor),
	}
	recMu.Lock()
	defer recMu.Unlock()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	if _, ok := recs[name]; !ok {
		recCh[name] = chainID
		t.Cleanup(func() {
			recMu.Lock()
			defer recMu.Unlock()
			out, err := json.Marshal(struct {
				ChainID string     `json:"chain_id"`
				Blocks  []recBlock `json:"blocks"`
			}{recCh[name], recs[name]})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name+".json"), out, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
	recs[name] = append(recs[name], b)
}
