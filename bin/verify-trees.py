#!/usr/bin/env python3
"""Rebuilds the note, identity, stake, stake nullifier and slash debt trees from the privacy index and checks them.

    bin/verify-trees.py [--db privacy_index.db] [--rpc https://rpc...] [--all-roots] [--no-chain]

Replays the indexed notes, identity writes and stake notes with Poseidon2
(services/zk, pinned to the chain's Go vectors) and compares:

- the latest root of each tree (every recorded root with --all-roots) with
  the root event the chain emitted for that block;
- the slash debt tree (an indexed tree, replayed from every debt row write
  in order) with the root the chain emitted after each write;
- the stake nullifier tree (an indexed tree, rebuilt in leaf-index order)
  with every proposal snapshot's nf_root at its nf_size;
- the rebuilt trees with the chain's own Query/Tree, Query/IdentityTree,
  Query/StakeTree, Query/StakeNullifierTree and Query/DebtTree (size, root
  and every row with its retained) at the index's synced height, over the
  RPC (skip with --no-chain).

Exit status 0 when everything matches, 1 on any mismatch, 2 when the chain
could not be asked.
"""
import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from services.privacy import store, verify  # noqa: E402
from services.privacy.rpc import CometRPC, RPCError  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=config.INDEX_DB)
    ap.add_argument("--rpc", default=config.INDEXER_RPC_URL)
    ap.add_argument("--all-roots", action="store_true", help="check every recorded root, not just the latest")
    ap.add_argument("--no-chain", action="store_true", help="check against the index's own root events only")
    args = ap.parse_args()

    conn = store.connect(args.db, readonly=True)
    started = time.monotonic()
    rep = verify.rebuild(conn, all_roots=args.all_roots)
    print(f"index synced to height {rep.synced_height}: {rep.note_size} notes ({rep.open_notes_checked} open, "
          f"commitments checked), {rep.identity_size} identity leaves, "
          f"{rep.stake_size} stake notes, {rep.debt_size} slash debt leaves ({rep.debt_writes_checked} row writes checked)")
    print(f"rebuilt in {time.monotonic() - started:.1f}s; {rep.roots_checked} recorded roots checked")
    print(f"note root     {rep.note_root.hex()}")
    print(f"identity root {rep.identity_root.hex()}")
    print(f"stake root    {rep.stake_root.hex() if rep.stake_root else '(empty)'}")
    print(f"stake nf root {rep.stake_nf_root.hex()} (size {rep.stake_nf_size}; "
          f"{rep.snapshots_checked} proposal snapshots checked)")
    print(f"debt root     {rep.debt_root.hex()} (size {rep.debt_size})")

    if not args.no_chain:
        async def ask():
            rpc = CometRPC(args.rpc)
            try:
                await verify.check_chain(rep, rpc, conn)
            finally:
                await rpc.close()

        try:
            asyncio.run(ask())
        except RPCError as exc:
            print(f"could not ask the chain: {exc}", file=sys.stderr)
            return 2
        print(f"compared with the chain at height {rep.synced_height} via {args.rpc}")

    for e in rep.errors:
        print(f"MISMATCH: {e}", file=sys.stderr)
    print("OK" if rep.ok else "FAILED")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
