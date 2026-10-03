#!/usr/bin/env bash
#
# Deploy a released tag to the backend's Akash lease, in place.
#
#   bin/deploy.sh v1.1.47           update the running deployment
#   bin/deploy.sh v1.1.47 --print   build the SDL and show it, submit nothing
#
# In place means the volume survives, so the replay database of used SSV
# transaction ids survives with it. That database is the only thing stopping a
# captured callback being replayed for another grant, so losing it matters more
# than it looks.
#
# The chain's node has its own repo and its own lease. Do not point this at that
# DSEQ, and do not lease this on the same provider as the node — EARTH_NODE_URL
# would then be a hairpin that hangs rather than fails.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:?usage: deploy.sh <tag> [--print]}"
MODE="${2:-}"

[ -f "$HERE/.env" ] || { echo "no .env — it holds the secrets injected into the submitted SDL" >&2; exit 1; }

# Read rather than source. An unquoted 24-word mnemonic in .env is executed as a
# command line by `source`, which is how two of its words once turned up as
# "command not found".
envget() { sed -n "s/^$1=//p" "$HERE/.env" | head -1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"; }
AKASH_API_KEY="$(envget AKASH_API_KEY)"
DSEQ="$(envget DSEQ)"
: "${AKASH_API_KEY:?set AKASH_API_KEY in .env}"
: "${DSEQ:?set DSEQ in .env — the deployment to update}"

WORK="$(mktemp -d)"; chmod 700 "$WORK"; trap 'rm -rf "$WORK"' EXIT

DIGEST="$("$HERE/bin/digest.sh" "$TAG")"
python3 "$HERE/bin/build-sdl.py" "$HERE" "$WORK/sdl.yaml" "$DIGEST"

if [ "$MODE" = "--print" ]; then
  # Secrets are in it, so this goes to stdout for a human, never to a file.
  cat "$WORK/sdl.yaml"; exit 0
fi

python3 -c "
import json,sys
json.dump({'data':{'sdl':open(sys.argv[1]).read()}}, open(sys.argv[2],'w'))
" "$WORK/sdl.yaml" "$WORK/body.json"

CODE=$(curl -sS -m 180 -X PUT \
  -H "x-api-key: ${AKASH_API_KEY}" -H 'content-type: application/json' \
  --data-binary @"$WORK/body.json" \
  "https://console-api.akash.network/v1/deployments/${DSEQ}" \
  -o "$WORK/resp.json" -w '%{http_code}')

# The response echoes the manifest, which carries the injected secrets, so a
# failure prints a redacted body rather than the raw one.
case "$CODE" in
  2??) echo "deployed $TAG to $DSEQ" ;;
  *)   echo "deploy failed (http $CODE)" >&2
       python3 -c "
import json,re,sys
raw=open(sys.argv[1]).read()
raw=re.sub(r'((?:MNEMONIC|TUNNEL_TOKEN|API_KEY)[^\s\",]*=)[^\"\\\\,\]\n]+', r'\1<redacted>', raw)
try:
    d=json.loads(raw)
    for k in ('manifest','sdl'):
        if isinstance(d,dict):
            if k in d.get('data',{}): d['data'][k]='<redacted>'
            if k in d: d[k]='<redacted>'
    raw=json.dumps(d)
except Exception: pass
sys.stderr.write(raw[:800]+chr(10))
" "$WORK/resp.json"
       exit 1 ;;
esac
