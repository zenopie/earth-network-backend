"""bin/verify-trees.py: rebuilding the trees catches an index that is wrong."""
import asyncio
import os
import subprocess
import sys

from services.privacy import verify
from services.privacy.indexer import Indexer
from services.privacy.store import Store
from tests.privacy_fixtures import FakeRPC, load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _indexed(path):
    store = Store(path)
    rpc = FakeRPC(load("TestPrivatePersonhood"))
    idx = Indexer(store, rpc)

    async def go():
        await idx.prepare()
        while await idx.step():
            pass

    asyncio.run(go())
    return store, rpc


def test_cli_passes_on_a_good_index(tmp_path):
    path = str(tmp_path / "i.db")
    _indexed(path)[0].close()
    out = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "verify-trees.py"), "--db", path, "--no-chain", "--all-roots"],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    assert "OK" in out.stdout


def test_a_tampered_commitment_is_caught(tmp_path):
    store, rpc = _indexed(str(tmp_path / "i.db"))
    store.conn.execute("UPDATE notes SET cm = ? WHERE position = 3", (bytes(31) + b"\x01",))
    rep = verify.rebuild(store.conn, all_roots=True)
    assert not rep.ok and any("note root" in e for e in rep.errors)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("chain root" in e for e in rep.errors)


def test_a_missed_zeroing_is_caught(tmp_path):
    store, rpc = _indexed(str(tmp_path / "i.db"))
    store.conn.execute("DELETE FROM identity_writes WHERE zeroed = 1")
    rep = verify.rebuild(store.conn)
    asyncio.run(verify.check_chain(rep, rpc))
    assert any("identity" in e for e in rep.errors)


def test_cli_exit_status_on_mismatch(tmp_path):
    path = str(tmp_path / "i.db")
    store, _ = _indexed(path)
    store.conn.execute("UPDATE notes SET cm = ? WHERE position = 0", (bytes(31) + b"\x02",))
    store.close()
    out = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "verify-trees.py"), "--db", path, "--no-chain"],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 1
    assert "MISMATCH" in out.stderr
