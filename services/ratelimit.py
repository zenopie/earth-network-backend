"""Per-client limits for /gas/register, in front of the expensive check.

`earthd gas-check` runs one at a time (gascheck: ~120 MB a proof on a 256 MiB
lease), so without a per-client bound one script could hold the queue and
every real registrant would wait behind its junk or be refused with 503. Two
limits, both in memory (one replica; a restart forgets them, which only
loosens them for a while):

- a sliding window: at most REGISTER_IP_MAX_PER_WINDOW requests per client in
  REGISTER_IP_WINDOW_SECONDS, counted on arrival, malformed ones included;
- concurrency: at most one gas-check per client at a time. A second request
  while the first is queued or running fails fast with 429 instead of taking
  another place in the queue.

The client is CF-Connecting-IP when TRUST_CF_CONNECTING_IP is on (the default:
the service is reachable only through the Cloudflare tunnel, so every request
reaches it from cloudflared and the peer address says nothing). Off, it is the
TCP peer. Only turn it on where Cloudflare is the sole ingress; anywhere else a
client chooses its own header and the limit is per-request.
"""
import time
from collections import deque
from contextlib import contextmanager

from fastapi import Request

import config

_windows: dict[str, deque] = {}
_busy: set[str] = set()


def client_ip(request: Request) -> str:
    if config.TRUST_CF_CONNECTING_IP:
        ip = request.headers.get("cf-connecting-ip", "").strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def allow(ip: str, now: float | None = None) -> bool:
    """Counts a request from ip; False when it is over the window's limit."""
    now = time.monotonic() if now is None else now
    since = now - config.REGISTER_IP_WINDOW_SECONDS
    if len(_windows) > config.REGISTER_IP_MAX_TRACKED:
        # Drop clients with nothing left in the window; if that frees nothing,
        # start over rather than grow without bound (a flood of distinct
        # addresses is not something a per-address limit stops anyway).
        for k in [k for k, q in _windows.items() if not q or q[-1] <= since]:
            del _windows[k]
        if len(_windows) > config.REGISTER_IP_MAX_TRACKED:
            _windows.clear()
    q = _windows.setdefault(ip, deque())
    while q and q[0] <= since:
        q.popleft()
    if len(q) >= config.REGISTER_IP_MAX_PER_WINDOW:
        return False
    q.append(now)
    return True


class Busy(Exception):
    """This client already has a check queued or running."""


@contextmanager
def one_at_a_time(ip: str):
    """Holds ip's single gas-check slot; raises Busy if it is taken."""
    if ip in _busy:
        raise Busy(ip)
    _busy.add(ip)
    try:
        yield
    finally:
        _busy.discard(ip)


def reset() -> None:
    _windows.clear()
    _busy.clear()
