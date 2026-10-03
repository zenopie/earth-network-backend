"""Recorded chain blocks, and a CometBFT RPC that serves them.

tests/fixtures/privacy/Test*.json.gz are real FinalizeBlock responses from the
chain's app scenario tests (real proofs, the launch genesis path), recorded by
bin/record-chain-fixtures.sh as the RPC's block_results JSON, each with the
note, identity and stake trees' sizes and roots after the block as the
keepers reported them (stake fields are absent from fixtures recorded before
the stake tree existed, and read as an empty tree).
"""
import gzip
import json
import os

from services.privacy.rpc import RPCError

DIR = os.path.join(os.path.dirname(__file__), "fixtures", "privacy")
# Every recorded scenario (bin/record-chain-fixtures.sh names them after the
# chain test that produced them).
SCENARIOS = tuple(sorted(f[:-len(".json.gz")] for f in os.listdir(DIR) if f.startswith("Test") and f.endswith(".json.gz")))


def load(name: str) -> dict:
    with gzip.open(os.path.join(DIR, f"{name}.json.gz")) as f:
        return json.load(f)


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field(num: int, value) -> bytes:
    if isinstance(value, int):
        return _varint(num << 3) + _varint(value) if value else b""
    return _varint(num << 3 | 2) + _varint(len(value)) + value if value else b""


def tree_response(block: dict) -> bytes:
    """QueryTreeResponse{tree_size=1, root=2 (hex string), anchor=3 RootRecord{root=1}}."""
    anchor = _field(1, bytes.fromhex(block["note_latest_root"]))
    return (_field(1, block["note_tree_size"]) + _field(2, block["note_current_root"].encode())
            + _varint(3 << 3 | 2) + _varint(len(anchor)) + anchor)


def identity_response(block: dict) -> bytes:
    """QueryIdentityTreeResponse{size=1, latest_root=2 (bytes)}."""
    return _field(1, block["identity_tree_size"]) + _field(2, bytes.fromhex(block["identity_latest_root"]))


def stake_tree_response(block: dict) -> bytes:
    """QueryStakeTreeResponse{size=1, root=2 (bytes)}."""
    return (_field(1, block.get("stake_tree_size", 0))
            + _field(2, bytes.fromhex(block.get("stake_latest_root", ""))))


class FakeRPC:
    """Serves a recorded scenario. `tip` limits what the chain has produced so far."""

    def __init__(self, scenario: dict, tip: int | None = None, earliest: int = 1):
        self.chain_id = scenario["chain_id"]
        self.blocks = {b["height"]: b for b in scenario["blocks"]}
        self.tip = tip if tip is not None else max(self.blocks)
        self.earliest = earliest
        self.calls: list[str] = []
        self.fail_next: Exception | None = None

    def _check(self, what):
        self.calls.append(what)
        if self.fail_next is not None:
            exc, self.fail_next = self.fail_next, None
            raise exc

    async def status(self):
        self._check("status")
        return {"chain_id": self.chain_id, "latest_height": self.tip, "earliest_height": self.earliest, "catching_up": False}

    async def block_results(self, height):
        self._check(f"block_results {height}")
        if height > self.tip or height not in self.blocks:
            raise RPCError(f"height {height} not available")
        return json.loads(json.dumps(self.blocks[height]["block_results"]))

    async def block_metas(self, lo, hi):
        from services.privacy.rpc import parse_time

        self._check(f"blockchain {lo}-{hi}")
        return {h: (self.blocks[h]["hash"], parse_time(self.blocks[h]["time"]))
                for h in range(lo, hi + 1) if h in self.blocks and h <= self.tip}

    async def abci_query(self, path, data=b"", height=None):
        self._check(f"abci_query {path} {height}")
        b = self.blocks[height]
        if path == "/earth.shielded.v1.Query/Tree":
            return tree_response(b)
        if path == "/earth.personhood.v1.Query/IdentityTree":
            return identity_response(b)
        if path == "/earth.shieldedstaking.v1.Query/StakeTree":
            return stake_tree_response(b)
        raise RPCError(f"unknown path {path}")

    async def close(self):
        pass


class ChainClient:
    """A TestClient that asks for /privacy/<x> under the base /privacy/status names,
    as a wallet does (/privacy/<chain_id>/<genesis>/<x>)."""

    def __init__(self, client):
        self.client = client
        self.base = client.get("/privacy/status").json()["base"]
        assert self.base, "the index holds no chain id / genesis yet"

    def get(self, path: str, **kw):
        if path.startswith("/privacy/") and path != "/privacy/status":
            path = self.base + path[len("/privacy"):]
        return self.client.get(path, **kw)


def seed_chain(path: str, chain_id: str = "earth-test", genesis_hash: str = "ab" * 32) -> None:
    """An index that has met its chain (prepare ran) but holds no blocks."""
    from services.privacy.store import Store

    store = Store(path)
    store.set_meta("chain_id", chain_id)
    store.set_meta("genesis_hash", genesis_hash)
    store.close()
