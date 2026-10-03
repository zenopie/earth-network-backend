"""Shared fixtures: a throwaway replay database and a gas router app."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from routers import gas  # noqa: E402
from services import replay  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(replay, "_conn", None)
    yield
    if replay._conn is not None:
        replay._conn.close()


@pytest.fixture
def client():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(gas.router)
    return TestClient(app)
