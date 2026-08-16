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

COPY . .

# Replay-protection state. Mount a volume here: a redeployed container with a
# fresh filesystem forgets which SSV transaction ids it has already honoured,
# and every one of them becomes replayable.
ENV STATE_DB=/app/state/ads_for_gas.db
RUN mkdir -p /app/state
VOLUME ["/app/state"]

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
