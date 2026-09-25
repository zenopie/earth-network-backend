"""The chain client's transport: bounded requests, and which faults may be retried."""
import socket
import threading
import time

import pytest
import requests
from cosmpy.aerial.client import LedgerClient

import config
from services import chain


@pytest.fixture
def silent_server():
    """A port that accepts connections and never answers."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    held = []
    stop = threading.Event()

    def accept():
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                held.append(sock.accept()[0])
            except OSError:
                pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    t.join()
    for c in held:
        c.close()
    sock.close()


def test_rest_calls_time_out(monkeypatch, silent_server):
    monkeypatch.setattr(config, "EARTH_NODE_URL", f"rest+http://127.0.0.1:{silent_server}")
    monkeypatch.setattr(config, "CHAIN_HTTP_TIMEOUT", 0.3)
    client = LedgerClient(chain._network())
    chain._bound_http(client)

    started = time.monotonic()
    with pytest.raises(requests.exceptions.ReadTimeout):
        client.query_bank_balance("earth1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu", "uerth")
    assert time.monotonic() - started < 5


class _Raising:
    def __init__(self, exc):
        self.exc = exc

    def send_tokens(self, *args, **kwargs):
        raise self.exc


def _send_with(monkeypatch, exc):
    monkeypatch.setattr(chain, "_client", _Raising(exc))
    monkeypatch.setattr(chain, "_wallet", object())
    return chain._send_blocking(object())


def test_a_read_timeout_on_broadcast_is_unresolved(monkeypatch):
    # The node may have accepted the tx before the response was lost.
    with pytest.raises(chain.SendUnresolved):
        _send_with(monkeypatch, requests.exceptions.ReadTimeout())


def test_a_connection_never_made_is_an_ordinary_failure(monkeypatch):
    with pytest.raises(requests.exceptions.ConnectTimeout):
        _send_with(monkeypatch, requests.exceptions.ConnectTimeout())

    refused = requests.exceptions.ConnectionError()
    try:
        requests.get("http://127.0.0.1:1", timeout=1)
    except requests.exceptions.ConnectionError as exc:
        refused = exc
    with pytest.raises(requests.exceptions.ConnectionError) as info:
        _send_with(monkeypatch, refused)
    assert not isinstance(info.value, chain.SendUnresolved)


def test_a_dropped_connection_is_unresolved(monkeypatch):
    with pytest.raises(chain.SendUnresolved):
        _send_with(monkeypatch, requests.exceptions.ConnectionError("Connection reset by peer"))
