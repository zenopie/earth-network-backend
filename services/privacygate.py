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

Canonical URLs only (audit-5 M2). The CDN keys on the full query string,
so every spelling of a page is another cache entry and another miss: an
unknown parameter (?cb=1, ?cb=2, ...), a repeated one, or an integer
spelled any other way than its plain decimal (0001000, %2B1000, +1000).
FastAPI took all of those as the same page, so one client could keep every
origin slot busy with misses. The gate answers each with 400, no-store,
before any handler runs: a query is name=value pairs joined by &, each name
one the endpoint takes, at most once and in alphabetical order (from_*
before limit; audit-6 L4), each value 0 or a decimal without a leading
zero, nothing percent-encoded. (An omitted parameter and its explicit
default are still two spellings; that is bounded, two per page.) A path that is not one of the
streams is 404, no-store. ENDPOINTS must list every /privacy route
(tests/test_audit5 checks it against the router).

CORS, for the web wallet: every /privacy response (refusals included)
carries Access-Control-Allow-Origin: PRIVACY_CORS_ORIGIN
(https://erth.network), whatever Origin asked. Fixed, not reflected: a CDN
keeps one copy of a page for every origin (Cloudflare ignores Vary:
Origin), so a reflected origin cached for one site would be served to
another. A request from a local dev origin (http://localhost[:port],
http://127.0.0.1[:port], when PRIVACY_CORS_LOCALHOST) gets its own origin
back instead, with Cache-Control: no-store so no CDN keeps that copy
(no Vary: Origin is needed, since a cacheable response never depends on
Origin). No
credentials, GET and HEAD only (an OPTIONS preflight is answered 204).
Nothing outside /privacy has CORS headers.
"""
import json
import re

import config
from services import ratelimit

PREFIX = "/privacy"

# Each stream under /privacy/<chain_id>/<genesis>/ and the query parameters it takes.
ENDPOINTS: dict[str, frozenset[str]] = {
    "status": frozenset(),
    "notes": frozenset({"from_pos", "limit"}),
    "nullifiers": frozenset({"from_height", "limit"}),
    "identity": frozenset({"from_index", "limit"}),
    "identity/zeroed": frozenset({"from_height", "limit"}),
    "roots/latest": frozenset(),
    "rates": frozenset({"epoch"}),
    "stake/notes": frozenset({"from_pos", "limit"}),
    "stake/nullifiers": frozenset({"from_height", "limit"}),
    "stake/nullifier-tree": frozenset({"from_index", "limit"}),
    "stake/roots": frozenset({"from_height", "limit"}),
    "stake/snapshots": frozenset({"from_height", "limit"}),
    "handles": frozenset({"from_index", "limit"}),
}
STATUS = PREFIX + "/status"  # the unkeyed status: no parameters
_SEGMENT = re.compile(r"[^/]+")
# A plain decimal: 0, or no leading zero; up to 20 digits (past int64 the
# handler answers 422).
_PAIR = re.compile(rb"([a-z_]{1,32})=(0|[1-9][0-9]{0,19})")
_LOCAL_ORIGIN = re.compile(r"http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?")


def _cors(origin: str | None) -> tuple[list[tuple[bytes, bytes]], bool]:
    """(CORS headers for a response to Origin `origin`, whether it must not be cached)."""
    local = bool(origin) and config.PRIVACY_CORS_LOCALHOST and _LOCAL_ORIGIN.fullmatch(origin) is not None
    allow = origin if local else config.PRIVACY_CORS_ORIGIN
    if not allow:
        return [], False
    return [(b"access-control-allow-origin", allow.encode("latin-1"))], local


def endpoint(path: str) -> str | None:
    """The stream a /privacy path names ("" for the unkeyed status), or None."""
    if path == STATUS:
        return ""
    parts = path[len(PREFIX) + 1:].split("/", 2) if path.startswith(PREFIX + "/") else []
    if len(parts) == 3 and _SEGMENT.fullmatch(parts[0]) and _SEGMENT.fullmatch(parts[1]) and parts[2] in ENDPOINTS:
        return parts[2]
    return None


def query_problem(name: str, query: bytes) -> str | None:
    """Why a query string is not the canonical spelling for stream `name`, or None."""
    if not query:
        return None
    allowed = ENDPOINTS.get(name, frozenset())
    seen = set()
    for pair in query.split(b"&"):
        m = _PAIR.fullmatch(pair)
        if m is None:
            return "each parameter must be name=<decimal integer, no leading zero, nothing encoded>"
        key = m.group(1).decode()
        if key not in allowed:
            return f"unknown parameter {key}; this stream takes {sorted(allowed) or 'none'}"
        if key in seen:
            return f"parameter {key} given twice"
        # One order (audit-6 L4): limit=..&from_pos=.. and from_pos=..&limit=..
        # were two cache keys for one page.
        if seen and key < max(seen):
            return f"parameters must be in alphabetical order ({' before '.join(sorted(allowed))})"
        seen.add(key)
    return None


async def _refuse(send, status: int, message: str, retry_after: int | None = None) -> None:
    body = json.dumps({"status": "error", "message": message}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
               (b"cache-control", b"no-store")]
    if retry_after is not None:
        headers.append((b"retry-after", str(retry_after).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _with_headers(send, extra: list, no_store: bool):
    """send, adding extra headers to the response start (and forcing no-store)."""
    if not extra:
        return send

    async def wrapped(message):
        if message["type"] == "http.response.start":
            headers = [(k, v) for k, v in message.get("headers") or []
                       if not (no_store and k.lower() == b"cache-control")]
            if no_store:
                headers.append((b"cache-control", b"no-store"))
            message = dict(message, headers=headers + extra)
        await send(message)
    return wrapped


async def _preflight(send) -> None:
    await send({"type": "http.response.start", "status": 204,
                "headers": [(b"access-control-allow-methods", b"GET, HEAD"),
                            (b"access-control-max-age", b"86400"), (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": b""})


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
        req = _Request(scope)
        cors, local = _cors(req.headers.get("origin"))
        send = _with_headers(send, cors, no_store=local)
        key = ratelimit.client_key(ratelimit.client_ip(req))
        if not ratelimit.allow_privacy(key):
            return await _refuse(send, 429, "too many requests; slow down", int(config.PRIVACY_IP_WINDOW_SECONDS))
        name = endpoint(scope["path"])
        if name is None:
            return await _refuse(send, 404, "no such stream; read base from /privacy/status")
        if scope.get("method") == "OPTIONS":
            return await _preflight(send)
        problem = query_problem(name, scope.get("query_string") or b"")
        if problem is not None:
            return await _refuse(send, 400, f"not a canonical URL: {problem}")
        if self.in_flight >= config.PRIVACY_MAX_CONCURRENT:
            return await _refuse(send, 503, "busy; try again shortly", 1)
        self.in_flight += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.in_flight -= 1
