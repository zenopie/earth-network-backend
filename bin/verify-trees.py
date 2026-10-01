#!/usr/bin/env python3
"""Rebuilds the note and identity trees from the privacy index and checks them.

    bin/verify-trees.py [--db privacy_index.db] [--rpc https://rpc...] [--all-roots] [--no-chain]

Replays the indexed notes and identity writes with Poseidon2 (services/zk,
pinned to the chain's Go vectors) and compares:

- the latest root of each tree (every recorded root with --all-roots) with
  the root event the chain emitted for that block;
- the rebuilt trees with the chain's own Query/Tree and Query/IdentityTree at
  the index's synced height, over the RPC (skip with --no-chain).

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
    print(f"index synced to height {rep.synced_height}: {rep.note_size} notes, {rep.identity_size} identity leaves")
    print(f"rebuilt in {time.monotonic() - started:.1f}s; {rep.roots_checked} recorded roots checked")
    print(f"note root     {rep.note_root.hex()}")
    print(f"identity root {rep.identity_root.hex()}")

    if not args.no_chain:
        async def ask():
            rpc = CometRPC(args.rpc)
            try:
                await verify.check_chain(rep, rpc)
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
