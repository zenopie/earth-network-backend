"""/circuits: the long-tail passport circuits, served byte for byte."""
import gzip
import os

from fastapi.testclient import TestClient

import main
from routers import circuits


def test_serves_the_file_unchanged(tmp_path, monkeypatch):
    body = gzip.compress(b'{"bytecode":"' + b"A" * 50_000 + b'"}', mtime=0)
    (tmp_path / "lean_poa_bp512_sha512.json.gz").write_bytes(body)
    monkeypatch.setattr(circuits, "DIR", str(tmp_path))
    c = TestClient(main.app)
    r = c.get("/circuits/lean_poa_bp512_sha512.json.gz", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"
    # Not compressed a second time by GZipMiddleware: the wallet hashes what
    # it inflates, once.
    assert r.headers.get("content-encoding") == "identity"
    assert r.content == body
    assert "immutable" in r.headers["cache-control"]


def test_refuses_anything_else(tmp_path, monkeypatch):
    (tmp_path / "secret.json.gz").write_bytes(b"x")
    monkeypatch.setattr(circuits, "DIR", str(tmp_path))
    c = TestClient(main.app)
    for name in ("secret.json.gz", "lean_poa_missing.json.gz", "..%2Fconfig.py", "lean_poa_x.json",
                 "lean_poa_X.json.gz"):
        assert c.get(f"/circuits/{name}").status_code == 404, name


def test_the_repo_carries_only_circuits():
    for name in os.listdir(circuits.DIR):
        assert circuits._NAME.fullmatch(name), name
