"""Admission for /privacy: a per-client rate and a cap on responses in flight.

The streams are public and cacheable; a CDN serves almost every request. What
reaches the origin is a miss, and the lease has 0.1 CPU and 256 MiB: a burst
of uncached pages, each a SQLite read, a JSON encode and a gzip, queued in
the threadpool (40 threads) and held their bodies in memory together
(audit-4 B3, poc_privacy_page_cost.py). This bounds both:

- PRIVACY_MAX_CONCURRENT responses in flight, counted from arrival until the
  last body byte is sent (pure ASGI, outside GZip, so the encode and the
  compression are inside the slot). Past it: 503, Retry-After: 1, no-store,
  at once rather than queued.
- PRIVACY_IP_MAX_PER_WINDOW requests per client in PRIVACY_IP_WINDOW_SECONDS
  (services/ratelimit's sliding window, the client keyed as for
  /gas/register). Past it: 429, Retry-After, no-store.

Page sizes are fixed and cursors aligned (routers/privacy), so the CDN
collapses every wallet onto the same URLs; deploy/akash/README.md has the
Cloudflare rate-limit rule that bounds misses before they reach the tunnel.
"""
import json

import config
from services import ratelimit

PREFIX = "/privacy"


async def _refuse(send, status: int, message: str, retry_after: int) -> None:
    body = json.dumps({"status": "error", "message": message}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                            (b"cache-control", b"no-store"), (b"retry-after", str(retry_after).encode())]})
    await send({"type": "http.response.body", "body": body})


class _Request:
    """The two attributes ratelimit.client_ip reads, from an ASGI scope."""

    def __init__(self, scope):
        self.headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        client = scope.get("client")
        self.client = type("C", (), {"host": client[0]})() if client else None


class PrivacyGate:
    def __init__(self, app):
        self.app = app
        self.in_flight = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(PREFIX):
            return await self.app(scope, receive, send)
        key = ratelimit.client_key(ratelimit.client_ip(_Request(scope)))
        if not ratelimit.allow_privacy(key):
            return await _refuse(send, 429, "too many requests; slow down", int(config.PRIVACY_IP_WINDOW_SECONDS))
        if self.in_flight >= config.PRIVACY_MAX_CONCURRENT:
            return await _refuse(send, 503, "busy; try again shortly", 1)
        self.in_flight += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.in_flight -= 1
