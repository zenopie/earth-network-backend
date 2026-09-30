#!/usr/bin/env python3
"""Create a NEW Akash lease for the backend, and point .env's DSEQ at it.

    bin/create.py <tag> --provider <akash1...>

deploy.sh only updates a lease in place. This is for the times one has to be
replaced — a resource change, or a host that cannot run what the image needs.
The second is why it exists: `earthd gas-check` links Barretenberg's prebuilt
verifier, which uses ADX, and a Haswell Xeon (no ADX) dies with "Illegal
instruction" on the first instruction. Akash cannot filter bids by CPU feature,
so the provider is named explicitly, and should be one already seen to run
earthd — the chain's own provider is.

A new lease is a new state volume: the grant history, and with it today's
per-passport and daily limits, starts empty. Close the old lease yourself once
the new one serves (DELETE /v1/deployments/<dseq>); until then both connectors
share the tunnel and Cloudflare splits requests between them.

The Console API facts are the ones earth-network-deploy/bin/create.sh learned:
create answers 201, and POST /v1/leases wants manifest and leases at the top
level.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://console-api.akash.network/v1"


def env() -> dict:
    out = {}
    for line in open(os.path.join(HERE, ".env")):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("'\"")
    return out


def call(method: str, path: str, key: str, body=None) -> tuple[int, dict]:
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("x-api-key", key)
    req.add_header("content-type", "application/json")
    req.add_header("user-agent", "curl/8.7.1")  # Cloudflare refuses urllib's
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode(errors="replace")[:600]}


def dig(o, key):
    if isinstance(o, dict):
        if key in o:
            return o[key]
        o = list(o.values())
    if isinstance(o, list):
        for v in o:
            r = dig(v, key)
            if r is not None:
                return r
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag")
    ap.add_argument("--provider", required=True)
    ap.add_argument("--deposit", type=float, default=5)
    a = ap.parse_args()
    e = env()
    key = e["AKASH_API_KEY"]

    digest = subprocess.check_output([os.path.join(HERE, "bin/digest.sh"), a.tag], text=True).strip()
    with tempfile.TemporaryDirectory() as work:
        sdl_path = os.path.join(work, "sdl.yaml")
        subprocess.check_call([sys.executable, os.path.join(HERE, "bin/build-sdl.py"), HERE, sdl_path, digest])
        sdl = open(sdl_path).read()

    code, created = call("POST", "/deployments", key, {"data": {"sdl": sdl, "deposit": a.deposit}})
    if code // 100 != 2:
        sys.exit(f"create failed (http {code}): {created}")
    dseq, manifest, owner = str(dig(created, "dseq")), dig(created, "manifest"), dig(created, "owner")
    print("created deployment", dseq)

    bid = None
    for _ in range(36):
        _, bids = call("GET", f"/bids/{dseq}", key)
        for x in bids.get("data", []) or []:
            b = x.get("bid", x)
            bid_id = b.get("bid_id") or b.get("id") or {}
            if bid_id.get("provider") == a.provider:
                bid = bid_id
        if bid:
            break
        time.sleep(5)
    if not bid:
        sys.exit(f"{a.provider} did not bid on {dseq}; close it (DELETE /v1/deployments/{dseq}) and try another")

    code, lease = call("POST", "/leases", key, {"manifest": manifest, "leases": [{
        "owner": owner, "dseq": dseq, "gseq": bid.get("gseq", 1), "oseq": bid.get("oseq", 1), "provider": a.provider,
    }]})
    if code // 100 != 2:
        sys.exit(f"lease failed (http {code}): {lease}")
    print(f"leased {dseq} on {a.provider}")

    path = os.path.join(HERE, ".env")
    lines = open(path).read().splitlines()
    old = next((l.split("=", 1)[1] for l in lines if l.startswith("DSEQ=")), "")
    lines = [f"DSEQ={dseq}" if l.startswith("DSEQ=") else l for l in lines]
    open(path, "w").write("\n".join(lines) + "\n")
    print(f"DSEQ in .env: {old or '(unset)'} -> {dseq}. Close {old} once {dseq} serves.")


if __name__ == "__main__":
    main()
