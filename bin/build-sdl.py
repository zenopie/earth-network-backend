#!/usr/bin/env python3
"""Build the SDL that gets submitted: deploy/akash/deploy.yaml + image digest +
secrets from .env.

The same arrangement as the chain's deploy repo, and for the same reason. Two
values must reach the provider and must not reach the repository:

    GAS_WALLET_MNEMONIC   the hot key the dust is sent from — spendable ERTH
    TUNNEL_TOKEN          anyone holding it can attach a replica to the tunnel
    CHAIN_EDGE_TOKEN      the backend's pass past the node's Cloudflare allowlist

Everything submitted reaches the provider regardless; that is what submitting
means. What this avoids is them being committed.

The rest of the service's configuration stays in deploy.yaml, where it is
documented next to the reasons for its values. .env is the source of truth only
for what cannot be written down.

    bin/build-sdl.py <repo> <out.yaml> <digest>
"""
import os
import re
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
# rpc.erth.network refuses JSON-RPC POSTs (gas-check) without it (services/edge).
edge = env.get("CHAIN_EDGE_TOKEN", "")
assert re.fullmatch(r"[A-Za-z0-9_-]{32,128}", edge), (
    "CHAIN_EDGE_TOKEN missing or malformed (32-128 of [A-Za-z0-9_-]); see example.env")
s = s.replace(anchor, anchor + "      - CHAIN_EDGE_TOKEN=%s\n" % edge)

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

# CF-Connecting-IP keys the per-client limits only while Cloudflare is the
# sole way in; a globally published app port lets clients choose their key.
if a.get("TRUST_CF_CONNECTING_IP", "true").lower() == "true":
    for e in svcs["app"].get("expose") or []:
        assert not any(t.get("global") for t in e.get("to") or []), (
            "TRUST_CF_CONNECTING_IP=true with app port %s published globally" % e.get("port"))

# cloudflared's metrics server also serves /debug/pprof, /config and /diag/*;
# it stays on loopback (audit-6 L3).
cmd = svcs["cloudflared"].get("command") or []
for i, arg in enumerate(cmd):
    if arg == "--metrics" or arg.startswith("--metrics="):
        addr = arg.split("=", 1)[1] if "=" in arg else (cmd[i + 1] if i + 1 < len(cmd) else "")
        assert addr.startswith("127.0.0.1:") or addr.startswith("localhost:"), (
            "cloudflared --metrics %s is not loopback: it serves pprof and /config" % addr)

# NO_LOGS: cloudflared at debug/trace logs every request's headers
# (CF-Connecting-IP included). Every spelling cloudflared 2026.9.3 accepts
# (cmd/cloudflared/cliutil/logger.go): --proto-loglevel is the old name of
# --transport-loglevel; --trace-output writes a runtime trace to a file; a
# --config file can set any of them where these checks cannot see.
LEVEL_FLAGS = ("--loglevel", "--transport-loglevel", "--proto-loglevel")
FILE_FLAGS = ("--logfile", "--log-directory", "--trace-output", "--config")
for i, arg in enumerate(cmd):
    if arg in LEVEL_FLAGS or arg.startswith(tuple(f + "=" for f in LEVEL_FLAGS)):
        lvl = arg.split("=", 1)[1] if "=" in arg else (cmd[i + 1] if i + 1 < len(cmd) else "")
        assert lvl not in ("debug", "trace"), "cloudflared %s %s logs client requests" % (arg, lvl)
    assert not (arg in FILE_FLAGS or arg.startswith(tuple(f + "=" for f in FILE_FLAGS))), (
        "cloudflared %s writes logs, traces or settings to or from disk (NO_LOGS.md)" % arg)
# cloudflared also reads each flag from a TUNNEL_* env var, which the command
# checks above never see; the command is the one place these are set.
for k in sorted(envmap("cloudflared")):
    assert k not in ("TUNNEL_LOGLEVEL", "TUNNEL_TRANSPORT_LOGLEVEL", "TUNNEL_PROTO_LOGLEVEL", "TUNNEL_LOGFILE",
                     "TUNNEL_LOGDIRECTORY", "TUNNEL_TRACE_OUTPUT", "TUNNEL_METRICS"), (
        "cloudflared env %s is refused: set it in command, where it is checked" % k)

assert a.get("EARTH_CHAIN_ID") == "earth-1"
assert int(a.get("DUST_UERTH", "0")) > 0, "DUST_UERTH must be positive"

print("services:   ", ", ".join(sorted(svcs)))
print("node:       ", node, " chain:", a.get("EARTH_CHAIN_ID"))
print("dust:       ", a.get("DUST_UERTH"), "uerth")
print("daily cap:  ", a.get("REGISTER_GRANT_MAX_PER_DAY", "500"), "register grants;",
      "per client:", a.get("REGISTER_IP_MAX_PER_WINDOW", "10"), "per", a.get("REGISTER_IP_WINDOW_SECONDS", "3600"), "s",
      " cf-ip:", a.get("TRUST_CF_CONNECTING_IP", "true"))
print("passport:    nullifier/address/date index", a.get("PASSPORT_NULLIFIER_INDEX", "2"),
      a.get("PASSPORT_ADDRESS_INDEX", "1"), a.get("PASSPORT_CURRENT_DATE_INDEX", "0"))
print("secrets:     GAS_WALLET_MNEMONIC(%d words), TUNNEL_TOKEN(%d chars), CHAIN_EDGE_TOKEN(%d chars)"
      % (len(mn.split()), len(tok), len(edge)))

open(out, "w").write(s)
print("wrote %s (%d bytes)" % (out, len(s)))
