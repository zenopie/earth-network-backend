# /routers/airdrop.py
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import time
from typing import Dict, List, Optional, Tuple

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from secret_sdk.core.wasm import MsgExecuteContract

import config
from dependencies import secret_client, wallet


# ------------- Merkle Builder (from user's script, adapted as a module) -------------

VERSION = "0.1.0"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class LCDClient:
    def __init__(self, base_url: str, timeout: int = 15, max_retries: int = 3, verbose: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict:
        url = f"{self.base_url}{path}"
        attempt = 0
        backoff = 1.0
        while True:
            try:
                if self.verbose:
                    print(f"[HTTP] GET {url} params={params}", file=sys.stderr)
                resp = requests.get(url, params=params, timeout=self.timeout)
                if resp.status_code >= 400:
                    raise requests.HTTPError(f"HTTP {resp.status_code}: {resp.text[:500]}")
                return resp.json()
            except Exception as e:
                attempt += 1
                if attempt > self.max_retries:
                    raise RuntimeError(f"HTTP GET failed after {self.max_retries} retries: {e}") from e
                if self.verbose:
                    print(f"[HTTP] error: {e}; retry {attempt}/{self.max_retries} in {backoff:.1f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 10.0)

    def fetch_validator_delegations(self, validator_addr: str, limit: int = 1000) -> List[Dict]:
        """
        Fetch all delegation_responses for a validator using pagination.
        Cosmos/Secret LCD path: /cosmos/staking/v1beta1/validators/{validator_addr}/delegations
        """
        delegations: List[Dict] = []
        next_key: Optional[str] = None
        while True:
            params = {"pagination.limit": str(limit)}
            if next_key:
                params["pagination.key"] = next_key
            data = self._get(f"/cosmos/staking/v1beta1/validators/{validator_addr}/delegations", params)
            items = data.get("delegation_responses") or data.get("delegations") or []
            if not isinstance(items, list):
                raise RuntimeError("Unexpected LCD response: 'delegation_responses' is not a list")
            delegations.extend(items)
            pagination = data.get("pagination") or {}
            next_key = pagination.get("next_key") or None
            if not next_key:
                break
        return delegations

    def fetch_latest_block_info(self) -> Tuple[Optional[int], Optional[str]]:
        """
        Return (height, time) from /cosmos/base/tendermint/v1beta1/blocks/latest.
        On failure, returns (None, None).
        """
        try:
            data = self._get("/cosmos/base/tendermint/v1beta1/blocks/latest")
            block = data.get("block") or {}
            header = block.get("header") or {}
            height_str = header.get("height")
            time_str = header.get("time")
            height = int(height_str) if height_str is not None else None
            return height, time_str
        except Exception as e:
            print(f"[WARN] Failed to fetch latest block info: {e}", file=sys.stderr)
            return None, None


# SDK helpers removed; using HTTP LCDClient above.


def aggregate_balances(delegation_responses: List[Dict], denom: str, verbose: bool = False) -> Tuple[Dict[str, int], int]:
    """
    Aggregate balance amounts by delegator address for the given denom.
    Returns (balances_map, total_amount).
    """
    by_addr: Dict[str, int] = {}
    total = 0
    for item in delegation_responses:
        delegation = item.get("delegation") or {}
        delegator = delegation.get("delegator_address")
        bal = item.get("balance") or {}
        item_denom = bal.get("denom")
        amount_str = bal.get("amount", "0")
        if denom and item_denom and item_denom != denom:
            continue
        if not delegator:
            continue
        try:
            amount = int(amount_str)
        except Exception:
            if "." in amount_str:
                amount = int(amount_str.split(".", 1)[0] or "0")
            else:
                if verbose:
                    print(f"[WARN] Skipping non-integer amount for {delegator}: {amount_str}", file=sys.stderr)
                continue
        if amount <= 0:
            continue
        by_addr[delegator] = by_addr.get(delegator, 0) + amount
        total += amount
    return by_addr, total


class MerkleTree:
    """
    Deterministic Merkle tree:
      - Leaves are bytes already hashed (sha256 of "address:amount").
      - At each level, pairs (a, b) are combined as sha256(sort(a, b) concat) when pair_sorted=True.
      - Odd handling:
          * duplicate: combine(a, a) for the last unpaired element.
          * promote:   carry 'a' up unchanged to the next level.
    """
    def __init__(self, leaf_hashes: List[bytes], pair_sorted: bool = True, odd_policy: str = "duplicate") -> None:
        if not leaf_hashes:
            raise ValueError("Cannot build Merkle tree with zero leaves")
        if odd_policy not in ("duplicate", "promote"):
            raise ValueError("odd_policy must be 'duplicate' or 'promote'")
        self.pair_sorted = pair_sorted
        self.odd_policy = odd_policy
        self.levels: List[List[bytes]] = []
        self._build(leaf_hashes)

    def _combine(self, a: bytes, b: Optional[bytes]) -> bytes:
        if b is None:
            return a
        if self.pair_sorted:
            data = (a + b) if (a <= b) else (b + a)
        else:
            data = a + b
        return _sha256(data)

    def _build(self, leaf_hashes: List[bytes]) -> None:
        current = list(leaf_hashes)
        self.levels = [current]
        while len(current) > 1:
            next_level: List[bytes] = []
            i = 0
            n = len(current)
            while i < n:
                a = current[i]
                b: Optional[bytes] = current[i + 1] if (i + 1) < n else None
                if b is None:
                    if self.odd_policy == "duplicate":
                        combined = self._combine(a, a)
                        next_level.append(combined)
                    else:
                        next_level.append(a)
                else:
                    combined = self._combine(a, b)
                    next_level.append(combined)
                i += 2
            current = next_level
            self.levels.append(current)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def root_hex(self) -> str:
        return "0x" + self.root.hex()

    def proof(self, leaf_index: int) -> List[str]:
        """
        Returns a proof as a list of hex-encoded sibling hashes (0x-prefixed).
        When odd_policy='promote' and an unpaired node is promoted, that level contributes no sibling.
        """
        proof: List[str] = []
        idx = leaf_index
        for level_i in range(0, len(self.levels) - 1):
            level = self.levels[level_i]
            n = len(level)
            has_right = (idx % 2 == 0 and idx + 1 < n)
            has_left = (idx % 2 == 1)
            sibling_hash: Optional[bytes] = None
            if has_right:
                sibling_hash = level[idx + 1]
            elif has_left:
                sibling_hash = level[idx - 1]
            else:
                # last node without sibling
                if self.odd_policy == "duplicate":
                    sibling_hash = level[idx]
                else:
                    sibling_hash = None
            if sibling_hash is not None:
                proof.append("0x" + sibling_hash.hex())
            idx = idx // 2
        return proof


def build_merkle_from_balances(
    balances: Dict[str, int],
    odd_policy: str = "duplicate",
    pair_sorted: bool = True,
) -> Tuple[MerkleTree, List[str], List[bytes], Dict[str, int]]:
    """
    Returns (tree, ordered_addresses, leaf_hashes, index_by_address).
    Addresses are sorted ascending to establish deterministic leaf order.
    """
    ordered_addrs = sorted(balances.keys())
    leaf_hashes: List[bytes] = []
    for addr in ordered_addrs:
        leaf_str = f"{addr}:{balances[addr]}"
        leaf_hashes.append(_sha256(leaf_str.encode("utf-8")))
    tree = MerkleTree(leaf_hashes, pair_sorted=pair_sorted, odd_policy=odd_policy)
    index_map = {addr: i for i, addr in enumerate(ordered_addrs)}
    return tree, ordered_addrs, leaf_hashes, index_map


# ------------- Persistence (SQLite) -------------

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "merkle_data.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS merkle_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                chain TEXT NOT NULL,
                lcd_url TEXT NOT NULL,
                validator_address TEXT NOT NULL,
                denom TEXT NOT NULL,
                leaf_encoding TEXT NOT NULL,
                hash_fn TEXT NOT NULL,
                pair_sorted INTEGER NOT NULL,
                odd_policy TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                block_height INTEGER,
                block_time TEXT,
                total_addresses INTEGER NOT NULL,
                total_amount TEXT NOT NULL,
                merkle_root TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS merkle_leaves (
                run_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                amount TEXT NOT NULL,
                leaf_hash TEXT,
                proof_json TEXT,
                PRIMARY KEY (run_id, address),
                FOREIGN KEY (run_id) REFERENCES merkle_runs(id) ON DELETE CASCADE
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_merkle_leaves_addr ON merkle_leaves(address)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_merkle_runs_time ON merkle_runs(generated_at)")
        conn.commit()
    finally:
        conn.close()


def _insert_run(meta: Dict) -> int:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO merkle_runs (
                version, chain, lcd_url, validator_address, denom,
                leaf_encoding, hash_fn, pair_sorted, odd_policy, generated_at,
                block_height, block_time, total_addresses, total_amount, merkle_root
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meta["version"],
                meta["chain"],
                meta["lcd_url"],
                meta["validator_address"],
                meta["denom"],
                meta["leaf_encoding"],
                meta["hash_fn"],
                1 if meta["pair_sorted"] else 0,
                meta["odd_policy"],
                meta["generated_at"],
                meta.get("block_height"),
                meta.get("block_time"),
                meta["total_addresses"],
                meta["total_amount"],
                meta["merkle_root"],
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _insert_leaves(run_id: int, leaves: Dict[str, str], leaf_hashes: Optional[Dict[str, str]], proofs: Dict[str, List[str]]) -> None:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        rows = []
        for addr, amt in leaves.items():
            proof_json = json.dumps(proofs.get(addr, []))
            lh = leaf_hashes.get(addr) if leaf_hashes else None
            rows.append((run_id, addr, str(amt), lh, proof_json))
        cur.executemany(
            "INSERT OR REPLACE INTO merkle_leaves (run_id, address, amount, leaf_hash, proof_json) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def _latest_run_row() -> Optional[sqlite3.Row]:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM merkle_runs ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def _get_claim(run_id: int, address: str) -> Optional[sqlite3.Row]:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT amount, leaf_hash, proof_json FROM merkle_leaves WHERE run_id = ? AND address = ?",
            (run_id, address),
        )
        return cur.fetchone()
    finally:
        conn.close()


# ------------- Scheduling job implementation -------------

def run_merkle_job(verbose: bool = False) -> Dict:
    """
    Executes the Merkle build, persists results in SQLite, and returns the metadata dict.
    Uses configuration from config.py and environment:
      - LCD URL: config.SECRET_LCD_URL
      - Validator: config.MERKLE_VALIDATOR (must be set)
      - Denom: config.MERKLE_DENOM
      - Pagination limit: config.MERKLE_LIMIT
      - Odd policy: config.MERKLE_ODD_POLICY
      - Include proofs: config.MERKLE_PROOFS in {"none","all"}
      - Include leaf hashes in DB: config.MERKLE_INCLUDE_LEAF_HASHES
    """
    validator = getattr(config, "MERKLE_VALIDATOR", "").strip()
    if not validator:
        raise RuntimeError("MERKLE_VALIDATOR not configured; cannot run Merkle job.")

    denom = "uscrt"
    limit = 1000
    odd_policy = "duplicate"
    proofs_scope = "all"
    include_leaf_hashes = False

    client = LCDClient(
        getattr(config, "SECRET_LCD_URL", ""),
        timeout=15,
        max_retries=3,
        verbose=verbose,
    )

    if verbose:
        print("[*] Fetching delegations...", file=sys.stderr)
    delegations = client.fetch_validator_delegations(validator, limit=limit)
    if verbose:
        print(f"[*] Retrieved {len(delegations)} delegation entries", file=sys.stderr)

    balances, total_amount_int = aggregate_balances(delegations, denom=denom, verbose=verbose)
    if not balances:
        raise RuntimeError("No balances aggregated. Check validator, denom, and LCD endpoint.")

    if verbose:
        print(f"[*] Aggregated {len(balances)} delegators; total {denom} = {total_amount_int}", file=sys.stderr)

    tree, ordered_addrs, leaf_hashes_list, index_map = build_merkle_from_balances(
        balances, odd_policy=odd_policy, pair_sorted=True
    )
    root_hex = tree.root_hex()

    height, block_time = client.fetch_latest_block_info()

    # Build proofs map if required
    proofs_map: Dict[str, List[str]] = {}
    if proofs_scope == "all":
        for addr in ordered_addrs:
            idx = index_map[addr]
            proofs_map[addr] = tree.proof(idx)

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    leaves_map: Dict[str, str] = {addr: str(balances[addr]) for addr in ordered_addrs}
    leaf_hashes_map: Optional[Dict[str, str]] = None
    if include_leaf_hashes:
        leaf_hashes_map = {addr: "0x" + leaf_hashes_list[i].hex() for i, addr in enumerate(ordered_addrs)}

    meta: Dict = {
        "version": VERSION,
        "chain": getattr(config, "SECRET_CHAIN_ID", "secret-4"),
        "lcd_url": getattr(config, "SECRET_LCD_URL", ""),
        "validator_address": validator,
        "denom": denom,
        "leaf_encoding": "address:amount",
        "hash_fn": "sha256",
        "pair_sorted": True,
        "odd_policy": odd_policy,
        "generated_at": generated_at,
        "block_height": height,
        "block_time": block_time,
        "total_addresses": len(ordered_addrs),
        "total_amount": str(total_amount_int),
        "merkle_root": root_hex,
    }

    run_id = _insert_run(meta)
    _insert_leaves(run_id, leaves_map, leaf_hashes_map, proofs_map)

    if verbose:
        print(f"[*] Merkle run {run_id} stored with root {root_hex}", file=sys.stderr)

    return meta


# ------------- FastAPI Router -------------

router = APIRouter(prefix="/airdrop", tags=["Airdrop"])


class RunMeta(BaseModel):
    merkle_root: str
    generated_at: str
    denom: str
    validator: str
    total_addresses: int
    total_amount: str
    block_height: Optional[int] = None
    block_time: Optional[str] = None


class ClaimResponse(BaseModel):
    address: str
    amount: str
    denom: str
    merkle_root: str
    proof: List[str]
    run_generated_at: str
    block_height: Optional[int] = None
    block_time: Optional[str] = None


@router.get("/current/meta", response_model=RunMeta)
def get_current_meta():
    """
    Returns metadata for the latest Merkle run.
    """
    row = _latest_run_row()
    if not row:
        raise HTTPException(status_code=404, detail="No merkle run found")
    return RunMeta(
        merkle_root=row["merkle_root"],
        generated_at=row["generated_at"],
        denom=row["denom"],
        validator=row["validator_address"],
        total_addresses=row["total_addresses"],
        total_amount=row["total_amount"],
        block_height=row["block_height"],
        block_time=row["block_time"],
    )


@router.get("/current/{address}", response_model=ClaimResponse)
def get_current_claim(address: str):
    """
    Returns the claim information (amount, merkle root, proof) for a given address from the latest run.
    """
    row = _latest_run_row()
    if not row:
        raise HTTPException(status_code=404, detail="No merkle run found")
    run_id = row["id"]
    claim = _get_claim(run_id, address)
    if not claim:
        raise HTTPException(status_code=404, detail="Address not found in latest snapshot")
    proof_list = []
    try:
        proof_list = json.loads(claim["proof_json"] or "[]")
    except Exception:
        proof_list = []
    return ClaimResponse(
        address=address,
        amount=str(claim["amount"]),
        denom=row["denom"],
        merkle_root=row["merkle_root"],
        proof=proof_list,
        run_generated_at=row["generated_at"],
        block_height=row["block_height"],
        block_time=row["block_time"],
    )




# Initialize DB schema at import time to ensure tables exist before first use
init_db()

def submit_airdrop_to_contract(merkle_root: str, total_stake: str) -> Dict:
    """
    Submit the new airdrop merkle root to the airdrop contract via ResetAirdrop message.

    Args:
        merkle_root: The merkle root hex string (0x-prefixed)
        total_stake: The total stake amount as a string

    Returns:
        Dict with transaction hash and status
    """
    try:
        # Get contract details
        contract_address = getattr(config, "AIRDROP_CONTRACT", "").strip()
        contract_hash = getattr(config, "AIRDROP_HASH", "").strip()

        if not contract_address or not contract_hash:
            raise RuntimeError("AIRDROP_CONTRACT or AIRDROP_HASH not configured")

        print(f"[AIRDROP] Submitting to contract {contract_address}", file=sys.stderr)
        print(f"[AIRDROP] Merkle root: {merkle_root}", file=sys.stderr)
        print(f"[AIRDROP] Total stake: {total_stake}", file=sys.stderr)

        # Create the ResetAirdrop execute message
        execute_msg = {
            "reset_airdrop": {
                "merkle_root": merkle_root,
                "total_stake": total_stake
            }
        }

        # Create MsgExecuteContract
        msg = MsgExecuteContract(
            sender=wallet.key.acc_address,
            contract=contract_address,
            msg=execute_msg,
            code_hash=contract_hash,
            encryption_utils=secret_client.encrypt_utils
        )

        # Broadcast transaction
        tx = wallet.create_and_broadcast_tx(msg_list=[msg], gas=500000, memo="Weekly airdrop reset")

        if tx.code != 0:
            raise RuntimeError(f"Broadcast failed: {tx.raw_log}")

        print(f"[AIRDROP] Transaction broadcast successful. TX: {tx.txhash}", file=sys.stderr)

        # Poll for transaction confirmation
        tx_info = None
        for i in range(15):  # Poll for ~15 seconds
            try:
                tx_info = secret_client.tx.tx_info(tx.txhash)
                if tx_info:
                    break
            except Exception as e:
                if "not found" in str(e).lower():
                    print(f"[AIRDROP] Polling for tx... attempt {i+1}/15", file=sys.stderr)
                    time.sleep(1)
                    continue
                # For other errors, log but don't fail
                print(f"[AIRDROP] Error polling transaction: {e}", file=sys.stderr)
                break

        if tx_info and tx_info.code != 0:
            raise RuntimeError(f"Transaction failed on-chain: {tx_info.logs}")

        print(f"[AIRDROP] Successfully submitted to contract. TX: {tx.txhash}", file=sys.stderr)

        return {
            "success": True,
            "txhash": tx.txhash,
            "merkle_root": merkle_root,
            "total_stake": total_stake
        }

    except Exception as e:
        print(f"[AIRDROP] Failed to submit to contract: {e}", file=sys.stderr)
        raise

def scheduled_weekly_job() -> None:
    """
    Safe wrapper for the APScheduler weekly job.
    - Generates merkle tree from validator delegations
    - Submits the new airdrop to the contract via ResetAirdrop
    - Skips execution when MERKLE_VALIDATOR is not configured.
    - Catches and logs exceptions so the scheduler does not bring down the app.
    """
    try:
        validator = getattr(config, "MERKLE_VALIDATOR", "").strip()
        if not validator:
            print("[AIRDROP] MERKLE_VALIDATOR not set; skipping scheduled Merkle job.", file=sys.stderr)
            return

        # Run merkle job and get metadata
        print("[AIRDROP] Running merkle job...", file=sys.stderr)
        meta = run_merkle_job(verbose=True)

        # Submit to contract
        print("[AIRDROP] Submitting airdrop to contract...", file=sys.stderr)
        submit_airdrop_to_contract(
            merkle_root=meta["merkle_root"],
            total_stake=meta["total_amount"]
        )

        print("[AIRDROP] Weekly job completed successfully", file=sys.stderr)

    except Exception as e:
        # Keep the app running; log the failure for inspection
        print(f"[AIRDROP] Scheduled Merkle job failed: {e}", file=sys.stderr)