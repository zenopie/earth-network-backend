#!/bin/sh
# Re-records tests/fixtures/privacy/Test*.json.gz from the chain's app tests.
#
#   bin/record-chain-fixtures.sh /path/to/earth-network-chain [ref] [/path/to/mobile/circuits]
#
# Exports the chain at ref (default HEAD) to a temporary directory, adds
# bin/chainrec's recorder, hooks it into the shielded and staking test envs'
# block helpers, and runs eleven scenario tests with real proofs: nine of the
# chain's and bin/chainrec's own TestRecordRedelegateSlashDebt (the chain's
# redelegation tests fund and move outside blocks) and
# TestRecordGroundworksLease (the chain's lease tests fake their ante). The recorded
# block_results are exactly what a node's RPC would serve for those blocks.
# Nothing in the chain repo is touched.
#
# The recorder's own scenario reads its proofs from bin/chainrec/proofs.
# When the chain's circuits change, pass the matching mobile circuits
# directory (nargo and bb on PATH): missing proofs are proven, and
# bin/chainrec/proofs is rewritten with every proof the chain's cache does
# not hold.
set -eu
CHAIN=$(cd "${1:?usage: $0 /path/to/chain-checkout [ref] [circuits]}" && pwd)
REF=${2:-HEAD}
CIRCUITS=${3:-}
[ -z "$CIRCUITS" ] || CIRCUITS=$(cd "$CIRCUITS" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/chain" "$TMP/rec"
git -C "$CHAIN" archive "$REF" | tar -x -C "$TMP/chain"
cp "$HERE/bin/chainrec/zz_record_fixture_test.go" "$HERE/bin/chainrec/zz_record_scenarios_test.go" "$TMP/chain/app/"
PROOFS="$TMP/chain/x/shieldedstaking/testdata/proofs"
ls "$PROOFS" > "$TMP/chain-proofs"
[ ! -d "$HERE/bin/chainrec/proofs" ] || cp -n "$HERE/bin/chainrec/proofs/"* "$PROOFS/"
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
(cd "$TMP/chain" && RECORD_DIR="$TMP/rec" EARTH_CIRCUITS="$CIRCUITS" GOFLAGS=-mod=mod go test ./app -count=1 -timeout 60m \
    -run 'TestPrivatePersonhood$|TestShieldedPoolEndToEnd$|TestPrivateStakingLifecycle$|TestStakeNotesOwnerLocked$|TestSelfBondCompounds$|TestDexAnmlPoolLiquidity$|TestStakeVoteConcurrentProposals$|TestStakeVoteManyNotesOneWeight$|TestGroundworksNoteVotes$|TestRecordRedelegateSlashDebt$|TestRecordGroundworksLease$')
if [ -n "$CIRCUITS" ]; then
    rm -rf "$HERE/bin/chainrec/proofs"
    mkdir "$HERE/bin/chainrec/proofs"
    ls "$PROOFS" | grep -vxF -f "$TMP/chain-proofs" | while read -r f; do cp "$PROOFS/$f" "$HERE/bin/chainrec/proofs/"; done
fi
for f in "$TMP"/rec/*.json; do
    gzip -9 -c "$f" > "$HERE/tests/fixtures/privacy/$(basename "$f").gz"
done
echo "recorded $(ls "$TMP"/rec | wc -l | tr -d ' ') fixtures from $(git -C "$CHAIN" rev-parse --short "$REF")"
