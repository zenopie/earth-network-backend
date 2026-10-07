"""The image and the deploy tooling: what the build context leaves out, how
the entrypoint drops root, the hashed dependency lock, and that bin/create.py
prints no secret.
"""
import os


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_secrets_and_state_stay_out_of_the_build_context():
    import fnmatch

    patterns = [l.strip().rstrip("/") for l in open(os.path.join(_ROOT, ".dockerignore"))
                if l.strip() and not l.startswith("#")]

    def match(parts: list[str], pat: list[str]) -> bool:
        # Docker's `*` stays within one path element, unlike fnmatch's.
        return len(parts) == len(pat) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pat))

    def ignored(path: str, pattern: str) -> bool:
        # Docker's `**/` matches any number of directories, none included;
        # a match on a directory takes everything under it.
        parts, pat = path.split("/"), pattern.split("/")
        starts = range(len(parts)) if pat[0] == "**" else [0]
        pat = pat[1:] if pat[0] == "**" else pat
        return any(match(parts[i:j], pat) for i in starts for j in range(i + 1, len(parts) + 1))

    # Nested ones too (audit-6 L5): a bare `*.db` matched only at the root.
    for name in (".env", ".env.local", "ads_for_gas.db", "privacy_index.db", ".venv", ".git",
                 "deploy/akash/.env", "state/x.db", "tests/fixtures/idx.db", "bin/.env.prod"):
        assert any(ignored(name, p) for p in patterns), name
    assert not any(ignored("example.env", p) for p in patterns)


def test_entrypoint_chowns_no_symlink_target_and_logs_no_client():
    import ast

    tree = ast.parse(open(os.path.join(_ROOT, "entrypoint.py")).read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") in ("chown", "execvp")]
    chown = [c for c in calls if c.func.attr == "chown"]
    assert chown and all(any(k.arg == "follow_symlinks" and k.value.value is False for k in c.keywords) for c in chown)
    (execvp,) = [c for c in calls if c.func.attr == "execvp"]
    argv = [e.value for e in execvp.args[1].elts]
    assert "--no-access-log" in argv and "--no-proxy-headers" in argv


def test_the_lock_pins_what_requirements_txt_pins():
    import re

    def pins(path):
        out = {}
        for line in open(os.path.join(_ROOT, path)):
            m = re.match(r"([A-Za-z0-9_.-]+)(\[[^\]]*\])?==([^\s\\]+)", line)
            if m:
                out[m.group(1).lower().replace("_", "-")] = m.group(3)
        return out
    top, lock = pins("requirements.txt"), pins("requirements.lock")
    for name, version in top.items():
        assert lock.get(name) == version, f"{name}: requirements.txt {version}, lock {lock.get(name)}"
    text = open(os.path.join(_ROOT, "requirements.lock")).read()
    assert text.count("==") == text.count("\n") - text.count("--hash") - 2, "every pin has hashes"
    docker = open(os.path.join(_ROOT, "Dockerfile")).read()
    assert "--require-hashes" in docker and "requirements.lock" in docker
    assert re.search(r"^FROM .*python:3\.11-slim@sha256:[0-9a-f]{64}$", docker, re.M)


def test_create_redacts_console_errors():
    import importlib.util
    import json

    spec = importlib.util.spec_from_file_location("create", os.path.join(_ROOT, "bin", "create.py"))
    create = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(create)
    words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    raw = json.dumps({"error": "bad manifest", "manifest": f"env: [GAS_WALLET_MNEMONIC={words}]",
                      "data": {"sdl": "TUNNEL_TOKEN=eyJhIjoi"},
                      "message": "GAS_WALLET_MNEMONIC=abandon,TUNNEL_TOKEN=eyJhIjoi AKASH_API_KEY=ak_123"})
    out = create.redact(raw)
    for secret in ("abandon", "eyJhIjoi", "ak_123"):
        assert secret not in out
    assert "bad manifest" in out
    assert "eyJhIjoi" not in create.redact("not json: TUNNEL_TOKEN=eyJhIjoi trailing")
    out = create.redact(json.dumps({"error": f"env [GAS_WALLET_MNEMONIC={words}] refused"}))
    assert not any(w in out for w in words.split())
    # R4-E-4: the edge token too, in JSON and in a non-JSON body.
    edge_tok = "Zq3" + "x" * 40
    assert edge_tok not in create.redact(json.dumps({"message": f"CHAIN_EDGE_TOKEN={edge_tok}"}))
    assert edge_tok not in create.redact(f"not json: CHAIN_EDGE_TOKEN={edge_tok} trailing")


def test_deploy_sh_redacts_the_edge_token():
    """bin/deploy.sh's inline redaction covers every *TOKEN* (R4-E-4)."""
    import re
    src = open(os.path.join(_ROOT, "bin", "deploy.sh")).read()
    assert "(?:MNEMONIC|TOKEN|API_KEY)" in src
    pat = re.compile(r'((?:MNEMONIC|TOKEN|API_KEY)[^\s",]*=)[^"\\,\]\n]+')
    assert "secretvalue" not in pat.sub(r"\1<redacted>", "CHAIN_EDGE_TOKEN=secretvalue")


def test_earthd_pin_is_one_version_and_sha_and_refuses_pre_relaunch():
    """BD-3: one ARG pair is the pin, and the build refuses a release that
    cannot check the relaunch MsgRegister."""
    import re
    docker = open(os.path.join(_ROOT, "Dockerfile")).read()
    versions = re.findall(r"(?m)^ARG EARTHD_VERSION=(\S+)$", docker)
    shas = re.findall(r"(?m)^ARG EARTHD_SHA256=(\S+)$", docker)
    assert len(versions) == 1 and len(shas) == 1
    assert re.fullmatch(r"[0-9a-f]{64}", shas[0])
    # The refusal itself, run as the build runs it: every v0.* by name, the
    # never-run v1.0.0 by its sha256 (a re-cut under that tag name passes).
    import subprocess
    guard = re.search(r"(?ms)^RUN (case \"\$\{EARTHD_VERSION\}\".*?grep -Eq '\^\[0-9a-f\]\{64\}\$')$", docker)
    assert guard, "the EARTHD_VERSION/EARTHD_SHA256 refusal moved"
    script = guard.group(1).replace("\\\n", " ")
    old_v100 = "16842a4579a6c88d7d57597a28b452f696e16d3e2b6483c6a820e491cc7db475"

    def builds(version, sha):
        env = {"PATH": os.environ.get("PATH", ""), "EARTHD_VERSION": version, "EARTHD_SHA256": sha}
        return subprocess.run(["sh", "-c", script], env=env, capture_output=True).returncode == 0

    assert not builds("v0.9.3", "a" * 64)
    assert not builds("v1.0.0", old_v100)
    assert not builds("v1.0.1", old_v100)
    assert builds("v1.0.0", "b" * 64)
    assert builds("v1.1.0", "c" * 64)
    assert not builds("v1.1.0", "not-a-sha")
    # Nothing else hard-codes a version or a checksum.
    assert docker.count("${EARTHD_VERSION}") >= 2 and docker.count("${EARTHD_SHA256}") >= 2
