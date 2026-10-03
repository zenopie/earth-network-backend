"""Shared fixtures: a throwaway replay database and a gas router app."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from routers import gas  # noqa: E402
from services import knowndsc, ratelimit, replay  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(replay, "_conn", None)
    ratelimit.reset()
    knowndsc.reset()
    yield
    if replay._conn is not None:
        replay._conn.close()


def gas_app():
    """The gas router behind the same body cap main.py installs."""
    from fastapi import FastAPI

    from services.bodylimit import BodyLimit

    app = FastAPI()
    app.add_middleware(BodyLimit)
    app.include_router(gas.router)
    return app


@pytest.fixture
def client():
    return TestClient(gas_app())
