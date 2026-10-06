"""/circuits: the long-tail passport circuits, served byte for byte."""
import gzip
import hashlib
import os

from fastapi.testclient import TestClient

import main
from routers import circuits

JSON = b'{"bytecode":"' + b"A" * 50_000 + b'"}'
SHA = hashlib.sha256(JSON).hexdigest()


def _repo(tmp_path, monkeypatch, sums=True):
    body = gzip.compress(JSON, mtime=0)
    (tmp_path / "lean_poa_bp512_sha512.json.gz").write_bytes(body)
    if sums:
        (tmp_path / "SHA256SUMS").write_text(f"{SHA}  lean_poa_bp512_sha512.json\n")
    monkeypatch.setattr(circuits, "DIR", str(tmp_path))
    return body


def test_serves_the_file_unchanged(tmp_path, monkeypatch):
    body = _repo(tmp_path, monkeypatch)
    c = TestClient(main.app)
    r = c.get("/circuits/lean_poa_bp512_sha512.json.gz", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"
    # Not compressed a second time by GZipMiddleware: the wallet hashes what
    # it inflates, once.
    assert r.headers.get("content-encoding") == "identity"
    assert r.content == body
    # The plain name is reused by the next circuit change: never immutable
    # (R3-BD-6), or a CDN keeps the old build for a year.
    assert r.headers["cache-control"] == circuits.SHORT


def test_content_addressed_name_is_immutable(tmp_path, monkeypatch):
    body = _repo(tmp_path, monkeypatch)
    c = TestClient(main.app)
    r = c.get(f"/circuits/lean_poa_bp512_sha512.{SHA}.json.gz")
    assert r.status_code == 200 and r.content == body
    assert r.headers["cache-control"] == circuits.IMMUTABLE


def test_another_builds_hash_is_not_served(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    c = TestClient(main.app)
    assert c.get(f"/circuits/lean_poa_bp512_sha512.{'0' * 64}.json.gz").status_code == 404
    # Without SHA256SUMS no hash is vouched for: 404, not the file.
    os.remove(tmp_path / "SHA256SUMS")
    assert c.get(f"/circuits/lean_poa_bp512_sha512.{SHA}.json.gz").status_code == 404


def test_refuses_anything_else(tmp_path, monkeypatch):
    (tmp_path / "secret.json.gz").write_bytes(b"x")
    monkeypatch.setattr(circuits, "DIR", str(tmp_path))
    c = TestClient(main.app)
    for name in ("secret.json.gz", "lean_poa_missing.json.gz", "..%2Fconfig.py", "lean_poa_x.json",
                 "lean_poa_X.json.gz", "SHA256SUMS", f"lean_poa_x.{SHA.upper()}.json.gz"):
        assert c.get(f"/circuits/{name}").status_code == 404, name


def test_the_repo_carries_only_circuits_and_their_sums():
    names = sorted(os.listdir(circuits.DIR))
    for name in names:
        m = circuits._NAME.fullmatch(name)
        assert name == circuits.SUMS or (m and m.group(2) is None), name
    assert set(circuits.sums()) == {n[:-len(".json.gz")] for n in names if n != circuits.SUMS}


def test_sums_match_the_inflated_circuits():
    """SHA256SUMS is what the content-addressed names vouch for: it must be
    the sha256 of each file's inflated JSON (the value the wallets pin)."""
    for variant, digest in circuits.sums().items():
        h = hashlib.sha256()
        with gzip.open(os.path.join(circuits.DIR, variant + ".json.gz")) as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        assert h.hexdigest() == digest, variant
