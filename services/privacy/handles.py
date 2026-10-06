"""The handle directory: x/personhood's Handles query, read whole at one height.

A handle (lowercase a-z, 0-9, -; 3..32 characters; no leading or trailing
dash) names a registered human's shielded address. The chain is only the
directory: a wallet paying a handle looks it up and makes a note to its
address privately. Looking one handle up on a server would tell that server
who is about to pay whom, so the backend serves the whole directory as a
full-range stream (routers/privacy {base}/handles) and nothing that answers
about a single handle.

Source: `/earth.personhood.v1.Query/Handles` over abci_query, every page at
one pinned height (the indexer's last applied block), so a snapshot is one
consistent state:

    QueryHandlesRequest   {start = 1 (string, exclusive; "" from the first),
                           limit = 2 (uint32; 0: 100, at most 1000)}
    QueryHandlesResponse  {handles = 1 (repeated HandleEntry),
                           next = 2 (the last handle returned; "" when done)}
    HandleEntry           {handle = 1, address = 2 ("erthz1..." bech32m),
                           status = 3 ("live" | "renewal" | "free"),
                           expires_at = 4 (int64), renewal_until = 5 (int64),
                           owner = 6 (the handle-scope nullifier holding it,
                           64 lowercase hex; "" for a handle never claimed)}

Status is the chain's at the block's time: live while time < expires_at
(it resolves), renewal until renewal_until (owner only, does not resolve),
then free until swept. A record changes only with an event
(a handle_* event: handle_bound, handle_released, which the sweep emits),
and a status only with time, so the indexer refreshes after a block with
one of those events, once the synced block time reaches the earliest
expires_at / renewal_until in the snapshot, and at least every
HANDLES_MAX_AGE_SECONDS — but at most every HANDLES_MIN_REFRESH_BLOCKS
blocks, page by page (pages(): each parsed in a worker thread, staged in
SQLite, the snapshot swapped whole at the end; audit-5 L4). /privacy
flags the snapshot stale once it is HANDLES_STALE_BLOCKS behind a handle
event (audit-5 L5).

Everything is checked against the chain's own rules before it replaces
the snapshot (a malformed answer keeps the previous one): handle format,
strictly increasing order across pages, a known status, an erthz1
address, renewal_until >= expires_at >= 0, an owner of 64 lowercase hex
characters or none, and a `next` that moves forward.

owner is what a wallet compares with its own handle-scope nullifier to know
a handle is its own; an entry merely naming its address is not. It is
already public (the claiming bind's membership nullifier; the handle
events carry it).
"""
import asyncio
import re
from dataclasses import dataclass

from .rpc import proto_fields, varint

HANDLES_QUERY = "/earth.personhood.v1.Query/Handles"
STATUSES = ("live", "renewal", "free")

# x/personhood/types ValidateHandle.
_HANDLE = re.compile(r"[a-z0-9][a-z0-9-]{1,30}[a-z0-9]")
# zk/privacy ShieldedAddress.Encode: bech32m, hrp "erthz", owner_pk || ek_pub.
_ADDRESS = re.compile(r"erthz1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,200}")
# x/personhood HandleEntry.owner: a 32-byte nullifier as lowercase hex, or "".
_OWNER = re.compile(r"(?:[0-9a-f]{64})?")


def valid_handle(handle: str) -> bool:
    return _HANDLE.fullmatch(handle) is not None


class Malformed(ValueError):
    """The chain's answer does not have the Handles query's shape."""


@dataclass(frozen=True)
class Entry:
    handle: str
    address: str
    status: str
    expires_at: int
    renewal_until: int
    owner: str = ""


def request(start: str, limit: int) -> bytes:
    """QueryHandlesRequest{start, limit}, canonical protobuf."""
    out = b""
    if start:
        s = start.encode()
        out += b"\x0a" + varint(len(s)) + s
    if limit:
        out += b"\x10" + varint(limit)
    return out


def _one(fields: dict, num: int, default):
    v = fields.get(num)
    return v[-1] if v else default


def _str(fields: dict, num: int, what: str) -> str:
    v = _one(fields, num, b"")
    if not isinstance(v, (bytes, bytearray)):
        raise Malformed(f"{what}: not a string")
    try:
        return bytes(v).decode()
    except UnicodeDecodeError as exc:
        raise Malformed(f"{what}: not UTF-8") from exc


def _int64(fields: dict, num: int, what: str) -> int:
    v = _one(fields, num, 0)
    if not isinstance(v, int):
        raise Malformed(f"{what}: not a varint")
    return v - (1 << 64) if v >= 1 << 63 else v


def parse_entry(raw: bytes) -> Entry:
    try:
        f = proto_fields(raw)
    except (ValueError, IndexError) as exc:
        raise Malformed(f"HandleEntry: {exc}") from exc
    e = Entry(_str(f, 1, "handle"), _str(f, 2, "address"), _str(f, 3, "status"),
              _int64(f, 4, "expires_at"), _int64(f, 5, "renewal_until"), _str(f, 6, "owner"))
    if not valid_handle(e.handle):
        raise Malformed(f"handle {e.handle!r} is not a handle")
    if e.status not in STATUSES:
        raise Malformed(f"handle {e.handle}: status {e.status!r}")
    if _ADDRESS.fullmatch(e.address) is None:
        raise Malformed(f"handle {e.handle}: address is not a shielded (erthz1) address")
    if e.expires_at < 0 or e.renewal_until < e.expires_at:
        raise Malformed(f"handle {e.handle}: expires_at {e.expires_at}, renewal_until {e.renewal_until}")
    if _OWNER.fullmatch(e.owner) is None:
        raise Malformed(f"handle {e.handle}: owner is not 64 lowercase hex characters")
    return e


def parse_page(raw: bytes) -> tuple[list[Entry], str]:
    """(entries, next) of a QueryHandlesResponse."""
    try:
        f = proto_fields(raw)
    except (ValueError, IndexError) as exc:
        raise Malformed(f"QueryHandlesResponse: {exc}") from exc
    entries = []
    for raw_entry in f.get(1, []):
        if not isinstance(raw_entry, (bytes, bytearray)):
            raise Malformed("handles: not a message")
        entries.append(parse_entry(bytes(raw_entry)))
    return entries, _str(f, 2, "next")


async def pages(rpc, height: int, *, limit: int = 1000, max_entries: int = 200_000):
    """The whole directory at height, page by page, in handle order: an async
    iterator of entry lists. Each page is parsed in a worker thread, never on
    the event loop, and only one page is held at a time (audit-5 L4).
    Raises Malformed or the RPC's error."""
    start, last, total = "", None, 0
    while True:
        raw = await rpc.abci_query(HANDLES_QUERY, request(start, limit), height=height)
        entries, nxt = await asyncio.to_thread(parse_page, raw)
        for e in entries:
            if last is not None and e.handle <= last:
                raise Malformed(f"handle {e.handle} after {last}: not in order")
            if start and e.handle <= start:
                raise Malformed(f"handle {e.handle} at or before start {start}")
            last = e.handle
        total += len(entries)
        if total > max_entries:
            raise Malformed(f"more than {max_entries} handles")
        if nxt and (not entries or nxt != entries[-1].handle):
            raise Malformed(f"next {nxt!r} is not the page's last handle")
        yield entries
        if not nxt:
            return
        start = nxt


async def fetch(rpc, height: int, *, limit: int = 1000, max_entries: int = 200_000) -> list[Entry]:
    """The whole directory at height as one list (tests and tools; the
    indexer streams pages() into the store instead)."""
    out: list[Entry] = []
    async for page in pages(rpc, height, limit=limit, max_entries=max_entries):
        out += page
    return out


def next_change(entries: list[Entry]) -> int | None:
    """The earliest block time at which a status in entries changes with time alone."""
    times = [e.expires_at for e in entries if e.status == "live"]
    times += [e.renewal_until for e in entries if e.status == "renewal"]
    return min(times) if times else None
