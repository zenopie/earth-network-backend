#!/usr/bin/env bash
#
# Resolve a released tag to the image digest the SDL should pin.
#
# CI deliberately writes the digest nowhere in the repo: committing it would
# put deployment state in a public repository and race anyone pushing at the
# same time. The digest is a property of what was published, so it is read
# from the registry at deploy time instead.
#
# No credentials. The package is public, which it has to be anyway or the Akash
# provider could not pull it.
#
#   bin/digest.sh v1.1.47
set -euo pipefail

TAG="${1:?usage: digest.sh <tag>}"
REPO="${IMAGE_REPO:-zenopie/earth-network-backend}"

TOKEN=$(curl -fsS "https://ghcr.io/token?scope=repository:${REPO}:pull&service=ghcr.io" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

# The digest is the manifest's own hash, which the registry returns in a header.
# Hashing the body yourself gives the same answer only if you request the exact
# media type it was pushed as, so take the header and do not compute it.
DIGEST=$(curl -fsSI \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://ghcr.io/v2/${REPO}/manifests/${TAG}" \
  | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')

[ -n "$DIGEST" ] || { echo "no digest for ${REPO}:${TAG}" >&2; exit 1; }
echo "ghcr.io/${REPO}@${DIGEST}"
