#!/bin/sh
# Regenerates tests/fixtures/privacy/zk_vectors.json from the chain's Go code.
#
#   bin/zk-vectors.sh /path/to/earth-network-chain [ref]
#
# Exports the chain at ref (default HEAD; committed code only, never a
# half-edited working tree) to a temporary directory, and runs bin/zkvectors
# in a throwaway module whose earth dependency points there. Nothing in the
# chain repo is touched.
set -eu
CHAIN=$(cd "${1:?usage: $0 /path/to/chain-checkout [ref]}" && pwd)
REF=${2:-HEAD}
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/chain" "$TMP/run"
git -C "$CHAIN" archive "$REF" | tar -x -C "$TMP/chain"
cp "$HERE/bin/zkvectors/main.go" "$TMP/run/"
cp "$TMP/chain/go.sum" "$TMP/run/"
GOVER=$(sed -n 's/^go //p' "$TMP/chain/go.mod")
cat > "$TMP/run/go.mod" <<MOD
module zkvectors

go $GOVER

require github.com/earth-network/earth v0.0.0
replace github.com/earth-network/earth => $TMP/chain
MOD
OUT=$(cd "$TMP/run" && GOFLAGS=-mod=mod go run .)
echo "$OUT" | python3 -m json.tool > "$HERE/tests/fixtures/privacy/zk_vectors.json"
echo "wrote tests/fixtures/privacy/zk_vectors.json from $(git -C "$CHAIN" rev-parse --short "$REF")"
