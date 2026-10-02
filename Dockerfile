# Dockerfile
#
# The service is one FastAPI app now, so this is a plain uvicorn image: no
# monero-wallet-rpc to fetch and no supervisor multiplexing processes.

FROM --platform=linux/amd64 python:3.11-slim

WORKDIR /app

COPY requirements.txt .

# build-essential stays: cosmpy's crypto dependencies fall back to building from
# source when there is no wheel for the platform. It is removed again in the same
# layer so it does not ship in the image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/*

# earthd, from the chain release, for `earthd gas-check` (services/gascheck.py):
# the chain's own personhood checks, run here. Fetched by version and pinned by
# checksum — the value is the release's checksums.txt entry — so what runs is
# what the release published. The tarball's lib/ holds libwasmvm and the C++
# runtime the proof verifier needs; earthd finds them at ../lib.
#
# Bump EARTHD_VERSION with the chain, together with its checksum: a circuit or
# parameter change the node has and this binary lacks means refusing proofs the
# chain would take. The shielded chain's gas-check takes MsgRegister without a
# creator and with idc/pc fields, which v0.9.x cannot parse: this must be the
# privacy release before /gas/register can pay anything on that chain.
ARG EARTHD_VERSION=v1.0.0
ARG EARTHD_SHA256=16842a4579a6c88d7d57597a28b452f696e16d3e2b6483c6a820e491cc7db475
RUN python -c "import hashlib, sys, tarfile, urllib.request; \
url = 'https://github.com/zenopie/earth-network-chain/releases/download/${EARTHD_VERSION}/earthd_${EARTHD_VERSION}_linux_amd64.tar.gz'; \
data = urllib.request.urlopen(url, timeout=120).read(); \
got = hashlib.sha256(data).hexdigest(); \
sys.exit(f'earthd checksum mismatch: {got}') if got != '${EARTHD_SHA256}' else None; \
open('/tmp/earthd.tgz', 'wb').write(data)" \
    && mkdir -p /opt/earthd && tar -xzf /tmp/earthd.tgz -C /opt/earthd && rm /tmp/earthd.tgz \
    && /opt/earthd/bin/earthd version
ENV EARTHD_BIN=/opt/earthd/bin/earthd

COPY . .

# Replay-protection state and the privacy index. Mount a volume here: a
# redeployed container with a fresh filesystem forgets which grants it has
# already paid, and the per-passport and daily limits start over. (The index
# would only re-sync from the chain, which takes a while.)
ENV STATE_DB=/app/state/ads_for_gas.db
ENV INDEX_DB=/app/state/privacy_index.db
RUN mkdir -p /app/state \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
VOLUME ["/app/state"]

EXPOSE 8000

# Starts as root only to hand the state volume to `app`; see entrypoint.py.
CMD ["python", "entrypoint.py"]
