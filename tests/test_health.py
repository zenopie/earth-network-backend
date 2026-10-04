"""/health: the hot wallet balance, read in the background (services/health)."""
import config


def test_health_serves_the_last_background_reading(monkeypatch):
    import asyncio

    from fastapi.testclient import TestClient

    import main
    from services import chain as chain_mod, health

    health.reset()
    reads = []
    monkeypatch.setattr(config, "GAS_ENABLED", True)
    monkeypatch.setattr(chain_mod, "balance", lambda: reads.append(1) or 1_000_000)
    monkeypatch.setattr(chain_mod, "wallet_address", lambda: "earth1hot")
    c = TestClient(main.app)
    assert c.get("/health").json() == {"status": "starting"}
    asyncio.run(health.refresh())
    for _ in range(50):
        r = c.get("/health")
    assert len(reads) == 1, "one LCD read, however many requests"
    assert r.json()["grants_remaining"] == 1_000_000 // config.DUST_UERTH
    assert r.headers["cache-control"] == f"public, max-age={int(config.HEALTH_REFRESH_SECONDS)}"

    def down():
        raise RuntimeError("http://lcd.internal:1317 refused")
    monkeypatch.setattr(chain_mod, "balance", down)
    asyncio.run(health.refresh())
    assert c.get("/health").json() == {"status": "degraded"}
    health.reset()
