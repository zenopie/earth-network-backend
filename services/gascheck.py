"""Asking the chain's own personhood checks, through `earthd gas-check`.

One question decides the grant, and it is the chain's to answer: would it
accept this registration, and for which passport (`registration`). The
earthd binary from the chain release answers it with the chain's own code,
reading live state from the node with plain store reads and verifying the
proof here, on this machine — so junk proofs cost this service CPU and the
chain nothing. See `earthd gas-check --help` in the chain repo.

One check at a time. A proof verification peaks near 120 MB, and this lease has
256 MiB beside a ~70 MB service; two at once would be killed. Waiting is
bounded, so a burst is refused quickly instead of queueing forever, and
routers/gas lets each client hold at most one place in it (services/ratelimit)
after every check that needs no proof verification has passed.

Two lanes. GAS_CHECK_RESERVED_WAITING of the GAS_CHECK_MAX_WAITING places
are kept for `priority` checks (routers/gas: a new passport from a Document
Signer the chain already knows, services/knowndsc), and a priority check
takes the slot ahead of any ordinary one waiting. Junk that fills the
ordinary lane neither refuses nor delays a registration in the reserved one.
"""
import asyncio
import json
from collections import deque
from contextlib import asynccontextmanager

import config


class _PrioritySlot:
    """A one-holder lock whose waiters are served priority first, FIFO within each."""

    def __init__(self) -> None:
        self._held = False
        self._queues = (deque(), deque())  # priority, ordinary

    def _release(self) -> None:
        for q in self._queues:
            while q:
                fut = q.popleft()
                if not fut.done():
                    fut.set_result(None)  # handed over: still held
                    return
        self._held = False

    @asynccontextmanager
    async def hold(self, priority: bool = False):
        if self._held:
            fut = asyncio.get_running_loop().create_future()
            self._queues[0 if priority else 1].append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                if fut.done() and not fut.cancelled():
                    self._release()  # it was handed to us as we were cancelled
                raise
        else:
            self._held = True
        try:
            yield
        finally:
            self._release()


_slot = _PrioritySlot()
_waiting = 0


def load() -> float:
    """How full the queue is, 0..1: checks waiting (or running) over GAS_CHECK_MAX_WAITING."""
    return min(1.0, _waiting / max(1, config.GAS_CHECK_MAX_WAITING))


class Unavailable(Exception):
    """The check could not be made (node unreachable, timed out, busy) — not a refusal."""


async def _reap(proc) -> None:
    """Kill a still-running earthd and wait for it, even if we are being cancelled."""
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await asyncio.shield(proc.wait())
    except asyncio.CancelledError:
        pass  # killed already; the shielded wait still reaps it


async def _run(args: list[str], stdin: bytes | None = None, priority: bool = False) -> dict:
    global _waiting
    places = config.GAS_CHECK_MAX_WAITING
    if not priority:
        places -= config.GAS_CHECK_RESERVED_WAITING
    if _waiting >= places:
        raise Unavailable("too many checks waiting")
    _waiting += 1
    try:
        async with _slot.hold(priority):
            proc = await asyncio.create_subprocess_exec(
                config.EARTHD_BIN, "gas-check", *args,
                "--node", config.EARTH_RPC_URL, "--home", config.EARTHD_HOME,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=config.GAS_CHECK_TIMEOUT)
            except asyncio.TimeoutError:
                await _reap(proc)
                raise Unavailable("gas-check timed out")
            except BaseException:
                # Cancelled (shutdown, reload, a cancelled task): the slot is
                # released on the way out, so the process must die with it, or
                # the next check starts a second ~120 MB earthd beside an orphan
                # on a 256 MiB lease (final audit BD-7).
                await _reap(proc)
                raise
    except FileNotFoundError as exc:
        raise Unavailable(f"{config.EARTHD_BIN} is not installed") from exc
    finally:
        _waiting -= 1

    if proc.returncode != 0:
        # A non-zero exit is the command failing to ask, never the chain saying
        # no; the chain's refusals come back as {"ok": false} with exit 0.
        last = err.decode("utf-8", "replace").strip().splitlines()[-1:]
        raise Unavailable(last[0] if last else "gas-check failed")
    try:
        return json.loads(out.decode().strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise Unavailable("gas-check printed no result") from exc


async def registration(msg: dict, priority: bool = False) -> dict:
    """{"ok": true, "nullifier", "switched"} or {"ok": false, "error"} for a MsgRegister in proto JSON."""
    return await _run(["registration"], json.dumps(msg).encode(), priority)

