// Recorder for tests/fixtures/privacy/*.json.gz. bin/record-chain-fixtures.sh
// copies this into an exported copy of the chain (never the chain repo) and
// hooks it into the app test envs' block helpers; each recorded test then
// writes every FinalizeBlock response, as CometBFT RPC block_results JSON,
// with the trees' sizes and roots after the block (note, identity, stake,
// stake nullifier, slash debt), the Groundworks positions (id, validator,
// split_expires_at) and the x/personhood Handles query's answer at the block
// (QueryHandlesResponse, protobuf, hex: the handle directory as the chain
// serves it, statuses at the block's time), to $RECORD_DIR.

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

	personhoodkeeper "github.com/earth-network/earth/x/personhood/keeper"
	personhoodtypes "github.com/earth-network/earth/x/personhood/types"
	sskeeper "github.com/earth-network/earth/x/shieldedstaking/keeper"
	sstypes "github.com/earth-network/earth/x/shieldedstaking/types"

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
	NfSize       uint64          `json:"stake_nf_tree_size"`
	NfRoot       string          `json:"stake_nf_current_root"`
	NfAnchor     string          `json:"stake_nf_latest_root"`
	Handles      []string        `json:"handles"`
	DebtSize     uint64          `json:"debt_tree_size"`
	DebtRoot     string          `json:"debt_current_root"`
	DebtTree     string          `json:"debt_tree"`
	Positions    []recPosition   `json:"positions"`
}

// recPosition is a Groundworks position as the keeper stores it after the
// block: what the indexer's positions table mirrors.
type recPosition struct {
	ID             uint64 `json:"id"`
	Validator      string `json:"validator"`
	SplitExpiresAt int64  `json:"split_expires_at"`
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
	nfsize, nfroot, nfanchor, _ := app.ShieldedStakingKeeper.StakeNullifierTree(ctx)
	// The whole directory, paged as an indexer pages it (limit 1, so a
	// recorded scenario exercises next/start): one hex QueryHandlesResponse
	// per page, the request it answered implied by the previous page's next.
	var handles []string
	hq := personhoodkeeper.NewQueryServerImpl(app.PersonhoodKeeper)
	for start := ""; ; {
		page, err := hq.Handles(ctx, &personhoodtypes.QueryHandlesRequest{Start: start, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		bz, err := page.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, hex.EncodeToString(bz))
		if page.Next == "" {
			break
		}
		start = page.Next
	}
	// The slash debt tree (chain dff3a9b): size and root, and the whole
	// Query/DebtTree answer at the block (rows, window_seconds, clear_before
	// at the block's time), protobuf, hex.
	droot, dsize, err := app.ShieldedStakingKeeper.DebtRoot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dq, err := sskeeper.NewQueryServerImpl(app.ShieldedStakingKeeper).DebtTree(ctx, &sstypes.QueryDebtTreeRequest{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	dbz, err := dq.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	positions := []recPosition{}
	if err := app.ShieldedStakingKeeper.Positions.Walk(ctx, nil, func(id uint64, p sstypes.Position) (bool, error) {
		positions = append(positions, recPosition{ID: id, Validator: p.Validator, SplitExpiresAt: p.SplitExpiresAt})
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
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
		NfSize: nfsize, NfRoot: hex.EncodeToString(nfroot), NfAnchor: hex.EncodeToString(nfanchor),
		Handles: handles,
		DebtSize: dsize, DebtRoot: hex.EncodeToString(droot), DebtTree: hex.EncodeToString(dbz),
		Positions: positions,
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
