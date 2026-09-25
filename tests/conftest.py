"""Shared fixtures: a real signing key standing in for Google's, a throwaway
replay database, and a chain whose sends are recorded instead of broadcast."""
import base64
import hashlib
import os
import sys
import time
from urllib.parse import quote

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# config reads the environment at import time.
os.environ.setdefault("ADMOB_AD_UNIT_ID", "ca-app-pub-1/1111")

from ecdsa import NIST256p, SigningKey  # noqa: E402
from ecdsa.util import sigencode_der  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from routers import ads  # noqa: E402
from services import chain, replay, ssv  # noqa: E402

KEY_ID = "1234"
AD_UNIT = "1111"
ADDRESS = "earth1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

_signing_key = SigningKey.generate(curve=NIST256p)


def signed_query(raw_prefix: str) -> str:
    """Signs a raw (encoded) query prefix the way Google does: over its decoded form."""
    from urllib.parse import unquote

    sig = _signing_key.sign(
        unquote(raw_prefix).encode("utf-8"), hashfunc=hashlib.sha256, sigencode=sigencode_der
    )
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{raw_prefix}&signature={sig_b64}&key_id={KEY_ID}"


def callback_prefix(**overrides) -> str:
    """A raw query prefix in Google's parameter order, each value percent-encoded."""
    params = {
        "ad_network": "5450213213286189855",
        "ad_unit": AD_UNIT,
        "custom_data": ADDRESS,
        "reward_amount": "1",
        "reward_item": "gas",
        "timestamp": str(int(time.time() * 1000)),
        "transaction_id": "tx-1",
        "user_id": "",
    }
    params.update(overrides)
    return "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items() if v is not None)


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(config, "ADMOB_AD_UNIT_IDS", frozenset({AD_UNIT}))
    monkeypatch.setattr(replay, "_conn", None)
    yield
    if replay._conn is not None:
        replay._conn.close()


@pytest.fixture
def sends(monkeypatch):
    """Records every address dust is sent to, in place of the chain."""
    sent: list[str] = []

    async def fake_send(address: str) -> str:
        sent.append(address)
        return f"HASH{len(sent)}"

    async def fake_keys(key_id: str) -> dict[str, str]:
        return {KEY_ID: _signing_key.get_verifying_key().to_pem().decode()}

    monkeypatch.setattr(chain, "send_dust", fake_send)
    monkeypatch.setattr(ssv, "keys_for", fake_keys)
    return sent


@pytest.fixture
def client():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(ads.router)
    return TestClient(app)


def call(client, query: str) -> dict:
    return client.get("/ads-callback?" + query).json()
