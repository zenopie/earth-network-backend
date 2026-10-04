#!/bin/sh
# Re-records tests/fixtures/privacy/Test*.json.gz from the chain's app tests.
#
#   bin/record-chain-fixtures.sh /path/to/earth-network-chain [ref]
#
# Exports the chain at ref (default HEAD) to a temporary directory, adds
# bin/chainrec's recorder, hooks it into the shielded and staking test envs'
# block helpers, and runs eight scenario tests with real proofs. The recorded
# block_results are exactly what a node's RPC would serve for those blocks.
# Nothing in the chain repo is touched.
set -eu
CHAIN=$(cd "${1:?usage: $0 /path/to/chain-checkout [ref]}" && pwd)
REF=${2:-HEAD}
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/chain" "$TMP/rec"
git -C "$CHAIN" archive "$REF" | tar -x -C "$TMP/chain"
cp "$HERE/bin/chainrec/zz_record_fixture_test.go" "$TMP/chain/app/"
python3 - "$TMP/chain" <<'PY'
import sys
root = sys.argv[1]
COMMIT = "\t_, err = e.app.Commit()\n\trequire.NoError(e.t, err)\n"
def hook(path, call):
    # Records right after the block helper's Commit (its only one).
    p = f"{root}/{path}"
    s = open(p).read()
    if s.count(COMMIT) != 1:
        sys.exit(f"{path}: block helper changed; update bin/record-chain-fixtures.sh")
    s = s.replace(COMMIT, f"{COMMIT}\t{call}\n", 1)
    open(p, "w").write(s)
hook("app/shielded_test.go",
     "recordBlock(e.t, e.app, e.height, e.now, shieldedtest.ChainID, res)")
hook("app/shieldedstaking_env_test.go",
     "recordBlock(e.t, e.app, e.height, e.now, ssChainID, res)")
PY
(cd "$TMP/chain" && RECORD_DIR="$TMP/rec" GOFLAGS=-mod=mod go test ./app -count=1 \
    -run 'TestPrivatePersonhood$|TestShieldedPoolEndToEnd$|TestPrivateStakingLifecycle$|TestStakeNotesOwnerLocked$|TestSelfBondCompounds$|TestDexAnmlPoolLiquidity$|TestStakeVoteConcurrentProposals$|TestStakeVoteManyNotesOneWeight$')
for f in "$TMP"/rec/*.json; do
    gzip -9 -c "$f" > "$HERE/tests/fixtures/privacy/$(basename "$f").gz"
done
echo "recorded $(ls "$TMP"/rec | wc -l | tr -d ' ') fixtures from $(git -C "$CHAIN" rev-parse --short "$REF")"
