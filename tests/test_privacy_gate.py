"""Admission for /privacy (services/privacygate): canonical URLs only, one
parameter order, CORS, the per-client rate and the in-flight cap."""
import asyncio

import pytest

import config
from services.privacygate import PrivacyGate
from tests.privacy_fixtures import BASE


@pytest.mark.parametrize("query", [
    "from_pos=1000&limit=1000&cb=1",       # an unknown parameter
    "from_pos=1000&limit=1000&cb=2",
    "from_pos=0001000&limit=1000",         # leading zeros
    "from_pos=%2B1000&limit=01000",        # encoded +, leading zero
    "from_pos=+1000",
    "from_pos=%31000",                     # an encoded digit
    "from_pos=1000&from_pos=1000",         # repeated
    "from_pos=1000&limit=1000&",           # an empty pair
    "from_pos=",
    "from_pos=-0",
    "epoch=1",                             # another stream's parameter
])
def test_only_the_canonical_spelling_of_a_page_reaches_a_handler(notes_index, query):
    r = notes_index.get(f"{BASE}/notes?{query}")
    assert r.status_code == 400, query
    assert r.headers["cache-control"] == "no-store"
    assert "canonical" in r.json()["message"]


def test_the_canonical_page_is_served(notes_index):
    rows = set()
    for query in ("from_pos=1000&limit=1000", "from_pos=1000", "from_pos=0"):
        r = notes_index.get(f"{BASE}/notes?{query}")
        assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
        rows.add(r.json()["notes"][0][0])
    assert rows == {1000, 0}
    assert notes_index.get(f"{BASE}/status").status_code == 200
    r = notes_index.get("/privacy/status?cb=1")
    assert r.status_code == 400 and r.headers["cache-control"] == "no-store"
    r = notes_index.get(f"{BASE}/notes/")
    assert r.status_code == 404 and r.headers["cache-control"] == "no-store"


def test_the_gate_knows_every_privacy_route():
    from fastapi import FastAPI

    from routers import privacy as privacy_router
    from services import privacygate

    app = FastAPI()
    app.include_router(privacy_router.router)
    base = "/privacy/{chain_id}/{genesis}/"
    for path, item in app.openapi()["paths"].items():
        name = "" if path == "/privacy/status" else path[len(base):]
        assert path == "/privacy/status" or path.startswith(base)
        params = {p["name"] for p in item["get"].get("parameters", []) if p["in"] == "query"}
        assert params == set(privacygate.ENDPOINTS.get(name, frozenset())), path
    assert len(app.openapi()["paths"]) == len(privacygate.ENDPOINTS) + 1


def test_privacy_parameters_have_one_order():
    from services.privacygate import query_problem

    assert query_problem("notes", b"from_pos=0&limit=1000") is None
    assert query_problem("notes", b"from_pos=0") is None
    assert query_problem("notes", b"limit=1000") is None
    assert "alphabetical" in query_problem("notes", b"limit=1000&from_pos=0")
    assert "alphabetical" in query_problem("handles", b"limit=1000&from_index=0")
    assert "twice" in query_problem("notes", b"from_pos=0&from_pos=0")


def test_privacy_names_the_web_origin_for_everyone(notes_index):
    for origin in ("https://erth.network", None, "https://evil.example"):
        h = {"origin": origin} if origin else {}
        r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers=h)
        assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
        assert r.headers["access-control-allow-origin"] == "https://erth.network", origin
        assert "access-control-allow-credentials" not in r.headers
    r = notes_index.get("/privacy/status", headers={"origin": "https://erth.network"})
    assert r.headers["access-control-allow-origin"] == "https://erth.network"
    # Refusals too, so the wallet can read the status.
    r = notes_index.get(f"{BASE}/notes?cb=1", headers={"origin": "https://erth.network"})
    assert r.status_code == 400 and r.headers["access-control-allow-origin"] == "https://erth.network"


def test_a_local_dev_origin_is_reflected_and_never_cached(notes_index):
    for origin in ("http://localhost:5173", "http://127.0.0.1:8080", "http://localhost"):
        r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers={"origin": origin})
        assert r.status_code == 200
        assert r.headers["access-control-allow-origin"] == origin
        assert r.headers["cache-control"] == "no-store"
    r = notes_index.get(f"{BASE}/notes?from_pos=1000", headers={"origin": "http://localhost.evil.example"})
    assert r.headers["access-control-allow-origin"] == "https://erth.network"


def test_a_preflight_is_answered(notes_index):
    r = notes_index.options(f"{BASE}/notes", headers={"origin": "https://erth.network",
                                                      "access-control-request-method": "GET"})
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "https://erth.network"
    assert "GET" in r.headers["access-control-allow-methods"]


def test_no_cors_outside_privacy():
    from fastapi.testclient import TestClient

    from services.privacygate import PrivacyGate
    from tests.gas_fixtures import gas_app

    app = gas_app()
    app.add_middleware(PrivacyGate)
    r = TestClient(app).get("/gas/pow", headers={"origin": "https://erth.network"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


def test_privacy_rate_limit_per_client(notes_index, monkeypatch):
    monkeypatch.setattr(config, "TRUST_CF_CONNECTING_IP", True)
    monkeypatch.setattr(config, "PRIVACY_IP_MAX_PER_WINDOW", 3)
    a, b = {"cf-connecting-ip": "203.0.113.1"}, {"cf-connecting-ip": "203.0.113.2"}
    for _ in range(3):
        assert notes_index.get("/privacy/status", headers=a).status_code == 200
    r = notes_index.get(BASE + "/notes", headers=a)
    assert r.status_code == 429 and r.headers["cache-control"] == "no-store" and r.headers["retry-after"]
    assert notes_index.get("/privacy/status", headers=b).status_code == 200, "another client is not limited"


def test_privacy_in_flight_cap():
    """Past PRIVACY_MAX_CONCURRENT the gate answers 503 at once; other paths pass."""
    release = asyncio.Event()
    entered = []

    async def slow_app(scope, receive, send):
        entered.append(scope["path"])
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    gate = PrivacyGate(slow_app)

    async def call(path):
        sent = []

        async def send(m):
            sent.append(m)

        async def receive():
            return {"type": "http.request", "body": b""}

        await gate({"type": "http", "path": path, "headers": [], "client": ("198.51.100.9", 1)}, receive, send)
        return sent[0]["status"]

    async def go():
        slots = [asyncio.create_task(call(BASE + "/notes")) for _ in range(config.PRIVACY_MAX_CONCURRENT)]
        await asyncio.sleep(0.01)
        refused = await call(BASE + "/notes")
        other = asyncio.create_task(call("/gas/pow"))
        await asyncio.sleep(0.01)
        release.set()
        return refused, await asyncio.gather(*slots), await other

    refused, ok, other = asyncio.run(go())
    assert refused == 503 and ok == [200] * config.PRIVACY_MAX_CONCURRENT and other == 200
    assert gate.in_flight == 0
