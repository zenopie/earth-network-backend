"""Request bodies are capped before they are parsed (services/bodylimit, re-audit K4).

Without the cap FastAPI reads and JSON-decodes a body of any size before the
handler and its per-client limit run: one ~50 MB body (Cloudflare passes up
to 100 MB) peaks far past the lease's 256 MiB.
"""
import asyncio
import json
import tracemalloc

import httpx
import pytest

import config
from tests.gas_fixtures import gas_app
from tests.gas_fixtures import REFERRAL, reg_body


def _junk_body(n_signals: int) -> bytes:
    return json.dumps({"proof": "", "public_signals": ["1"] * n_signals, "signature_algorithm": "", "dsc_der": "",
                       "idc": "", "pc_anml": "", "pc_erth": "", "ciphertext_anml": "", "ciphertext_erth": "",
                       "pc_gas": "", "ciphertext_gas": ""}).encode()


async def _post(content, headers=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gas_app()), base_url="http://t", timeout=60) as c:
        return await c.post("/gas/register", content=content, headers={"content-type": "application/json", **(headers or {})})


def test_a_large_declared_body_is_refused_before_it_is_read():
    body = _junk_body(2_000_000)  # ~10 MiB
    assert len(body) > 8 * 2**20
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        resp = asyncio.run(_post(body))
        peak = tracemalloc.get_traced_memory()[1] - base
    finally:
        tracemalloc.stop()
    assert resp.status_code == 413
    # Nothing body-sized was decoded: the body itself is the only large object.
    assert peak < 2 * 2**20, f"peak {peak / 2**20:.1f} MiB"


def test_a_chunked_body_is_cut_off_at_the_cap():
    chunk = b" " * 16384
    sent = 0

    async def stream():
        nonlocal sent
        for _ in range(4096):  # 64 MiB if it were all read
            sent += len(chunk)
            yield chunk

    resp = asyncio.run(_post(stream()))
    assert resp.status_code == 413
    assert sent <= config.MAX_BODY_BYTES + 2 * len(chunk)


def test_a_bad_content_length_is_refused():
    async def go():
        async def app_receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = []

        async def send(m):
            sent.append(m)
        from services.bodylimit import BodyLimit
        await BodyLimit(gas_app())({"type": "http", "method": "POST", "path": "/gas/register",
                                    "headers": [(b"content-length", b"lots")]}, app_receive, send)
        return sent[0]["status"]
    assert asyncio.run(go()) == 413


def test_the_largest_real_registration_fits(client, monkeypatch):
    import base64

    from services import gascheck

    async def refuse(msg, priority=False):
        return {"ok": False, "error": "stand-in"}
    monkeypatch.setattr(gascheck, "registration", refuse)
    # A 32 KiB proof and an 8 KiB certificate, the chain's own maxima.
    body = reg_body(proof=base64.b64encode(b"\x01" * 32 * 1024).decode(),
                    dsc_der=base64.b64encode(b"\x02" * 8 * 1024).decode(),
                    **REFERRAL)
    body["affiliate_handle"] = "h" * 32  # the longest handle
    body["public_signals"] = reg_body(**{**REFERRAL, "affiliate_handle": "h" * 32})["public_signals"] + ["7"] * 11
    assert len(json.dumps(body)) < config.MAX_BODY_BYTES
    assert client.post("/gas/register", json=body).status_code == 403  # reached gas-check


@pytest.mark.parametrize("over", [
    {"proof": "A" * 50_000},
    {"dsc_der": "A" * 12_000},
    {"pc_gas": "A" * 4096},
    {"public_signals": ["1"] * 65},
    {"public_signals": ["1" * 200]},
    {"signature_algorithm": "x" * 300},
])
def test_over_long_fields_fail_validation(client, over):
    resp = client.post("/gas/register", json=reg_body(**over))
    assert resp.status_code in (413, 422)
