"""Per-client and global limits for /gas/register, in front of the expensive check.

`earthd gas-check` runs one at a time (gascheck: ~120 MB a proof on a 256 MiB
lease), so without bounds one script could hold the queue and every real
registrant would wait behind its junk or be refused. All of it in memory (one
replica; a restart forgets it, which only loosens the limits for a while).

The client is a network, not an address: an IPv4 /32, or the IPv6 prefix of
REGISTER_IPV6_PREFIX bits (default /64, the smallest block an ISP hands a
subscriber; /56 is stricter, for a flood from one customer's delegation). One
/64 is 2^64 addresses, so a per-address key is no limit at all against IPv6.

Per client:

- a sliding window: at most REGISTER_IP_MAX_PER_WINDOW requests in
  REGISTER_IP_WINDOW_SECONDS, counted on arrival, malformed ones included. A
  sliding-window counter (this window's count, the last one's, weighted by
  overlap), so every client costs one fixed-size entry however many requests
  it makes. At most REGISTER_IP_MAX_TRACKED clients are kept; past that the
  least recently seen is evicted (and gets a fresh budget if it comes back),
  never the whole table.
- concurrency: at most one gas-check per client at a time. A second request
  while the first is queued or running fails fast with 429.

Globally, the refusal budget: gas-check refusals (the chain would not accept
the registration — junk that passed every cheap check) are counted over a
minute. Past REGISTER_REFUSALS_PER_MINUTE the service sheds: a request that
does not qualify for the reserved lane (routers/gas) is refused with 429
before it can take a place in the queue.

The client address is CF-Connecting-IP when TRUST_CF_CONNECTING_IP is on
(right only where Cloudflare is the sole ingress — the Akash lease is
tunnel-only, so every request reaches it from cloudflared and the peer
address says nothing). Off (the default), it is the TCP peer. Anywhere else a
client chooses its own header and the limit is per-request.
"""
import ipaddress
import time
from collections import OrderedDict
from contextlib import contextmanager

from fastapi import Request

import config

# client key -> packed (window index << 32 | previous count << 16 | count).
# One small int per client, ordered least recently seen first.
_windows: "OrderedDict[int | str, int]" = OrderedDict()
_busy: set = set()
# The refusal budget's own sliding-window counter: [minute index, previous, count].
_refusals = [0, 0, 0]

_V6_TAG = 1 << 128  # keeps an IPv6 prefix's key apart from every IPv4 address's


def client_ip(request: Request) -> str:
    if config.TRUST_CF_CONNECTING_IP:
        ip = request.headers.get("cf-connecting-ip", "").strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def client_key(ip: str) -> int | str:
    """The network a request is limited as: an IPv4 /32 or an IPv6 /REGISTER_IPV6_PREFIX.

    An IPv4-mapped IPv6 address is its IPv4 address. Anything unparseable is
    keyed as given (only the TCP peer or a trusted header reaches here).
    """
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip[:64]
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return int(addr.ipv4_mapped)
        bits = max(0, min(128, config.REGISTER_IPV6_PREFIX))
        return _V6_TAG | (int(addr) >> (128 - bits))
    return int(addr)


def _count(entry: int, now: float, window: float) -> tuple[int, int, int]:
    """(window index, previous count, count) of a packed entry, rolled forward to now."""
    idx = int(now // window)
    e_idx, prev, cur = entry >> 32, (entry >> 16) & 0xFFFF, entry & 0xFFFF
    if e_idx == idx:
        return idx, prev, cur
    if e_idx == idx - 1:
        return idx, cur, 0
    return idx, 0, 0


def _estimate(prev: int, cur: int, now: float, window: float) -> float:
    overlap = 1.0 - (now % window) / window
    return prev * overlap + cur


def allow(key, now: float | None = None) -> bool:
    """Counts a request from client key; False when it is over the window's limit."""
    now = time.monotonic() if now is None else now
    window = config.REGISTER_IP_WINDOW_SECONDS
    entry = _windows.pop(key, 0)
    idx, prev, cur = _count(entry, now, window)
    ok = _estimate(prev, cur, now, window) < config.REGISTER_IP_MAX_PER_WINDOW
    if ok:
        cur = min(cur + 1, 0xFFFF)
    _windows[key] = idx << 32 | prev << 16 | cur  # re-inserted: now the most recent
    while len(_windows) > config.REGISTER_IP_MAX_TRACKED:
        _windows.popitem(last=False)
    return ok


def note_refusal(now: float | None = None) -> None:
    """Counts one gas-check refusal against the global budget."""
    now = time.monotonic() if now is None else now
    idx, prev, cur = _count(_refusals[0] << 32 | _refusals[1] << 16 | _refusals[2], now, 60.0)
    _refusals[:] = [idx, prev, min(cur + 1, 0xFFFF)]


def shedding(now: float | None = None) -> bool:
    """Whether the refusal budget is spent: new, unqualified requests get 429."""
    if config.REGISTER_REFUSALS_PER_MINUTE <= 0:
        return False
    now = time.monotonic() if now is None else now
    _, prev, cur = _count(_refusals[0] << 32 | _refusals[1] << 16 | _refusals[2], now, 60.0)
    return _estimate(prev, cur, now, 60.0) >= config.REGISTER_REFUSALS_PER_MINUTE


class Busy(Exception):
    """This client already has a check queued or running."""


@contextmanager
def one_at_a_time(key):
    """Holds key's single gas-check slot; raises Busy if it is taken."""
    if key in _busy:
        raise Busy(key)
    _busy.add(key)
    try:
        yield
    finally:
        _busy.discard(key)


def reset() -> None:
    _windows.clear()
    _busy.clear()
    _refusals[:] = [0, 0, 0]
