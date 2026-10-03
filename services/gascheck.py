"""Asking the chain's own personhood checks, through `earthd gas-check`.

One question decides the grant, and it is the chain's to answer: would it
accept this registration, and for which passport (`registration`). The earthd binary from the chain release answers them with the chain's own code,
reading live state from the node with plain store reads and verifying any proof
here, on this machine — so junk proofs cost this service CPU and the chain
nothing. See `earthd gas-check --help` in the chain repo.

One check at a time. A proof verification peaks near 120 MB, and this lease has
256 MiB beside a ~70 MB service; two at once would be killed. Waiting is
bounded, so a burst is refused quickly instead of queueing forever.
"""
import asyncio
import json
import logging

import config

logger = logging.getLogger(__name__)

_slot = asyncio.Semaphore(1)
_waiting = 0


class Unavailable(Exception):
    """The check could not be made (node unreachable, timed out, busy) — not a refusal."""


async def _run(args: list[str], stdin: bytes | None = None) -> dict:
    global _waiting
    if _waiting >= config.GAS_CHECK_MAX_WAITING:
        raise Unavailable("too many checks waiting")
    _waiting += 1
    try:
        async with _slot:
            proc = await asyncio.create_subprocess_exec(
                config.EARTHD_BIN, "gas-check", *args,
                "--node", config.EARTH_RPC_URL, "--home", config.EARTHD_HOME,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=config.GAS_CHECK_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise Unavailable("gas-check timed out")
    except FileNotFoundError as exc:
        raise Unavailable(f"{config.EARTHD_BIN} is not installed") from exc
    finally:
        _waiting -= 1

    if proc.returncode != 0:
        # A non-zero exit is the command failing to ask, never the chain saying
        # no; the chain's refusals come back as {"ok": false} with exit 0.
        raise Unavailable(err.decode("utf-8", "replace").strip().splitlines()[-1:] or "gas-check failed")
    try:
        return json.loads(out.decode().strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise Unavailable("gas-check printed no result") from exc


async def registration(msg: dict) -> dict:
    """{"ok": true, "nullifier", "switched"} or {"ok": false, "error"} for a MsgRegister in proto JSON."""
    return await _run(["registration"], json.dumps(msg).encode())

