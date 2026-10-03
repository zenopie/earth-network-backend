"""The few CometBFT RPC calls the indexer makes, over plain JSON-RPC GETs.

CometBFT v0.38 (the chain's): event attributes are plain strings, and
block_results carries txs_results plus one finalize_block_events list.
"""
import base64
import datetime

import httpx


class RPCError(Exception):
    """The node answered with an error, or not at all. Retryable."""


def parse_time(value: str) -> int:
    """RFC 3339 with up to nanoseconds -> unix seconds (floor), as BlockTime().Unix()."""
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    main, _, rest = v.partition(".")
    if rest:
        # Drop the fraction (Python takes at most microseconds), keep the offset.
        i = 0
        while i < len(rest) and rest[i].isdigit():
            i += 1
        v = main + rest[i:]
    return int(datetime.datetime.fromisoformat(v).timestamp())


class CometRPC:
    def __init__(self, url: str, timeout: float = 20.0, client: httpx.AsyncClient | None = None):
        self.url = url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, **params) -> dict:
        try:
            resp = await self._client.get(f"{self.url}/{method}", params={k: v for k, v in params.items() if v is not None})
        except httpx.HTTPError as exc:
            raise RPCError(f"{method}: {exc.__class__.__name__}") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise RPCError(f"{method}: HTTP {resp.status_code}, not JSON") from exc
        if "error" in body and body["error"]:
            err = body["error"]
            raise RPCError(f"{method}: {err.get('message', '')} {err.get('data', '')}".strip())
        if "result" not in body:
            raise RPCError(f"{method}: HTTP {resp.status_code}, no result")
        return body["result"]

    async def status(self) -> dict:
        r = await self._call("status")
        sync = r["sync_info"]
        return {
            "chain_id": r["node_info"]["network"],
            "latest_height": int(sync["latest_block_height"]),
            "earliest_height": int(sync.get("earliest_block_height") or 1),
            "catching_up": bool(sync.get("catching_up")),
        }

    async def block_results(self, height: int) -> dict:
        return await self._call("block_results", height=height)

    async def block_metas(self, lo: int, hi: int) -> dict[int, tuple[str, int, str]]:
        """{height: (block hash, unix time, parent hash)} for lo..hi; the node returns at most 20 a call.

        The parent is the header's last_block_id: the hash the block commits
        to as the one before it ("" at the chain's first block).
        """
        out: dict[int, tuple[str, int, str]] = {}
        while lo <= hi:
            r = await self._call("blockchain", minHeight=lo, maxHeight=min(hi, lo + 19))
            for m in r.get("block_metas") or []:
                h = int(m["header"]["height"])
                parent = ((m["header"].get("last_block_id") or {}).get("hash")) or ""
                out[h] = (m["block_id"]["hash"], parse_time(m["header"]["time"]), parent)
            lo = min(hi, lo + 19) + 1
        return out

    async def abci_query(self, path: str, data: bytes = b"", height: int | None = None) -> bytes:
        r = await self._call("abci_query", path=f'"{path}"', data="0x" + data.hex(), height=height)
        resp = r.get("response") or {}
        if int(resp.get("code") or 0) != 0:
            raise RPCError(f"abci_query {path}: code {resp.get('code')}: {resp.get('log', '')}")
        return base64.b64decode(resp.get("value") or "")


def proto_fields(message: bytes) -> dict[int, list]:
    """A protobuf message's fields by number: varints as ints, length-delimited as bytes.

    Enough to read the handful of query responses the indexer and the
    verification tool need without generating the chain's protos.
    """
    out: dict[int, list] = {}
    i = 0

    def varint() -> int:
        nonlocal i
        shift = v = 0
        while True:
            b = message[i]
            i += 1
            v |= (b & 0x7F) << shift
            if not b & 0x80:
                return v
            shift += 7

    while i < len(message):
        key = varint()
        num, wt = key >> 3, key & 7
        if wt == 0:
            val = varint()
        elif wt == 2:
            n = varint()
            val = message[i:i + n]
            if len(val) != n:
                raise ValueError("truncated length-delimited field")
            i += n
        elif wt == 1:
            val = message[i:i + 8]
            i += 8
        elif wt == 5:
            val = message[i:i + 4]
            i += 4
        else:
            raise ValueError(f"unsupported wire type {wt}")
        out.setdefault(num, []).append(val)
    return out


def varint_field(message: bytes, number: int) -> int:
    """The value of a varint field in a protobuf message (0 if absent)."""
    v = proto_fields(message).get(number)
    return v[-1] if v else 0
