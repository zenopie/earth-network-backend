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
