#!/bin/sh
# Regenerates tests/fixtures/privacy/zk_vectors.json from the chain's Go code.
#
#   bin/zk-vectors.sh /path/to/earth-network-chain
#
# Builds bin/zkvectors in a temporary module whose earth dependency is replaced
# by the given checkout, so nothing in the chain repo is touched.
set -eu
CHAIN=$(cd "${1:?usage: $0 /path/to/chain-checkout}" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp "$HERE/bin/zkvectors/main.go" "$TMP/"
cp "$CHAIN/go.sum" "$TMP/"
GOVER=$(sed -n 's/^go //p' "$CHAIN/go.mod")
cat > "$TMP/go.mod" <<MOD
module zkvectors

go $GOVER

require github.com/earth-network/earth v0.0.0
replace github.com/earth-network/earth => $CHAIN
MOD
cd "$TMP" && GOFLAGS=-mod=mod go run . | python3 -m json.tool > "$HERE/tests/fixtures/privacy/zk_vectors.json"
echo "wrote tests/fixtures/privacy/zk_vectors.json"
