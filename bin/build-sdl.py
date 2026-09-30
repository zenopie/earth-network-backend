#!/usr/bin/env python3
"""Build the SDL that gets submitted: deploy/akash/deploy.yaml + image digest +
secrets from .env.

The same arrangement as the chain's deploy repo, and for the same reason. Two
values must reach the provider and must not reach the repository:

    GAS_WALLET_MNEMONIC   the hot key the dust is sent from — spendable ERTH
    TUNNEL_TOKEN          anyone holding it can attach a replica to the tunnel

Everything submitted reaches the provider regardless; that is what submitting
means. What this avoids is them being committed.

The rest of the service's configuration stays in deploy.yaml, where it is
documented next to the reasons for its values. .env is the source of truth only
for what cannot be written down.

    bin/build-sdl.py <repo> <out.yaml> <digest>
"""
import os
import sys

repo, out, digest = sys.argv[1], sys.argv[2], sys.argv[3]

env = {}
for line in open(os.path.join(repo, ".env")):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    v = v.strip()
    # Strip surrounding quotes the way `source .env` would. A quoted mnemonic
    # is the safe way to write one — unquoted, its words are parsed as commands
    # by anything that sources the file — but the quotes must not survive into
    # the value or BIP-39 rejects it.
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    env[k.strip()] = v

s = open(os.path.join(repo, "deploy/akash/deploy.yaml")).read()

# --- pin the image -----------------------------------------------------------
old = [l for l in s.splitlines() if l.strip().startswith("image: ghcr.io/zenopie/earth-network-backend")]
assert len(old) == 1, "expected exactly one backend image line, found %d" % len(old)
s = s.replace(old[0].strip(), "image: %s" % digest)
print("pinned image to %s" % digest.split("@")[-1][:20] + "…")

# --- inject the secrets ------------------------------------------------------
# The app service's env list is the first `    env:` in the file; cloudflared's
# is the `    env: []` further down. Both are asserted rather than assumed, so a
# reordering of the file fails here instead of silently putting a mnemonic in
# the wrong service.
anchor = "    env:\n"
assert s.count(anchor) == 1, "app env anchor moved (found %d)" % s.count(anchor)
mn = env.get("GAS_WALLET_MNEMONIC", "")
assert len(mn.split()) in (12, 24), "GAS_WALLET_MNEMONIC missing or malformed"
assert not any(c in mn for c in "\"'"), "mnemonic carries quote characters; BIP39 will reject it"
assert mn == mn.strip(), "mnemonic has leading/trailing whitespace"
s = s.replace(anchor, anchor + "      - GAS_WALLET_MNEMONIC=%s\n" % mn)

anchor = "    env: []\n"
assert s.count(anchor) == 1, "cloudflared env anchor moved"
tok = env.get("TUNNEL_TOKEN", "")
assert tok.startswith("eyJ"), "tunnel token missing or not a JWT"
s = s.replace(anchor, "    env:\n      - TUNNEL_TOKEN=%s\n" % tok)

# --- sanity, before it is submitted ------------------------------------------
import yaml  # noqa: E402

d = yaml.safe_load(s)
svcs = d["services"]
assert set(svcs) == {"app", "cloudflared"}, sorted(svcs)


def envmap(name):
    return dict(e.split("=", 1) for e in (svcs[name].get("env") or []))


a = envmap("app")

# A provider hostname here is the documented way this service hangs: from inside
# that provider's cluster it is a hairpin back to itself, cosmpy blocks in
# FastAPI's startup event, and the pod still reports ready. The tunnel hostname
# has no such failure mode.
node = a.get("EARTH_NODE_URL", "")
assert node, "EARTH_NODE_URL unset"
assert "provider." not in node, (
    "EARTH_NODE_URL is a provider hostname (%s). Use the tunnel — "
    "rest+https://lcd.erth.network — or this hangs on startup if it is ever "
    "leased on the same provider as the chain." % node)

# The app id an attestation must name. Wrong here, every iOS grant is refused.
assert a.get("IOS_APP_ID", "").count(".") >= 2, "IOS_APP_ID must be TEAMID.bundle.id"

assert a.get("EARTH_CHAIN_ID") == "earth-1"
assert int(a.get("DUST_UERTH", "0")) > 0, "DUST_UERTH must be positive"

print("services:   ", ", ".join(sorted(svcs)))
print("node:       ", node, " chain:", a.get("EARTH_CHAIN_ID"))
print("dust:       ", a.get("DUST_UERTH"), "uerth")
print("ios app:    ", a.get("IOS_APP_ID"), " development keys:", a.get("APP_ATTEST_ALLOW_DEVELOPMENT", "true"))
certs = [d for d in a.get("ANDROID_SIGNING_CERT_SHA256", "").split(",") if d.strip()]
for d in certs:
    assert len(bytes.fromhex(d.replace(":", "").strip())) == 32, "ANDROID_SIGNING_CERT_SHA256 entry is not a SHA-256: %s" % d
print("android:    ", a.get("ANDROID_PACKAGE", "network.erth.wallet"), " signing certs:", len(certs) or "NONE (Android grants off)",
      " locked bootloader:", a.get("ANDROID_REQUIRE_LOCKED_BOOTLOADER", "true"))
print("secrets:     GAS_WALLET_MNEMONIC(%d words), TUNNEL_TOKEN(%d chars)" % (len(mn.split()), len(tok)))

open(out, "w").write(s)
print("wrote %s (%d bytes)" % (out, len(s)))
