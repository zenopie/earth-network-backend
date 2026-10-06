"""A cap on request bodies, enforced before anything parses them.

FastAPI reads and JSON-decodes a body in full before the handler (and its
per-client limit) runs, and Cloudflare forwards bodies of up to 100 MB. On a
256 MiB lease one such request is enough to be killed, and a JSON array of
small strings decodes to many times its own size. The largest legitimate body
is a /gas/register: a 32 KiB proof and an 8 KiB certificate in base64 plus a
few hundred bytes of fields, about 56 KiB, so MAX_BODY_BYTES (64 KiB) refuses
nothing real.

Pure ASGI rather than BaseHTTPMiddleware so that nothing is buffered: a
declared Content-Length over the cap is refused before a byte is read, and a
chunked body is counted as it streams and refused the moment it crosses it.
"""
import json

from starlette.exceptions import HTTPException

import config


class BodyTooLarge(HTTPException):
    """Raised from receive() once a streamed body passes the cap. An
    HTTPException, so FastAPI's body parsing re-raises it (any other error
    there becomes a 400) and the app answers 413 itself."""

    def __init__(self) -> None:
        super().__init__(status_code=413, detail=f"request body over {config.MAX_BODY_BYTES} bytes")


async def _send_413(send) -> None:
    body = json.dumps({"status": "error", "message": f"request body over {config.MAX_BODY_BYTES} bytes"}).encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                            (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = config.MAX_BODY_BYTES
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    return await _send_413(send)
                if declared > limit:
                    return await _send_413(send)

        seen = 0
        started = False

        async def counted_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise BodyTooLarge()
            return message

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except BodyTooLarge:
            if not started:
                await _send_413(send)
