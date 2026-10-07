"""services/edge: the backend's Cloudflare credential, sent to our hosts only, over https only."""
import asyncio
import base64

import httpx
import pytest

import config
from services import edge, gascheck
from services.privacy.rpc import CometRPC

TOK = "t" * 43


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(config, "CHAIN_EDGE_TOKEN", TOK)
    monkeypatch.setattr(config, "CHAIN_EDGE_HOSTS", frozenset({"rpc.erth.network", "lcd.erth.network"}))


def test_header_is_basic_auth_for_our_hosts_only(token):
    want = "Basic " + base64.b64encode(f"earth-backend:{TOK}".encode()).decode()
    assert edge.headers("https://rpc.erth.network:443") == {"Authorization": want}
    assert edge.headers("rest+https://lcd.erth.network") == {"Authorization": want}
    assert edge.headers("https://RPC.erth.network/") == {"Authorization": want}
    # An operator's own node, or a look-alike host, never sees it.
    for url in ("https://rpc.example.org", "https://rpc.erth.network.evil.test", "http://localhost:26657"):
        assert edge.headers(url) == {}, url


def test_never_over_plain_http(token):
    """R4-E-5: an http:// URL to one of our hosts would carry the token in the
    clear to whatever answers port 80."""
    for url in ("http://rpc.erth.network", "rest+http://lcd.erth.network", "http://rpc.erth.network:443"):
        assert edge.headers(url) == {}, url
        assert edge.node_flag(url) == url, url


def test_plain_http_to_our_host_with_a_token_stops_startup(token, monkeypatch):
    monkeypatch.setattr(config, "EARTH_RPC_URL", "http://rpc.erth.network")
    with pytest.raises(RuntimeError) as e:
        edge.check()
    assert "EARTH_RPC_URL" in str(e.value) and TOK not in str(e.value)


def test_https_to_our_hosts_starts(token, monkeypatch):
    monkeypatch.setattr(config, "EARTH_RPC_URL", "https://rpc.erth.network:443")
    monkeypatch.setattr(config, "INDEXER_RPC_URL", "https://rpc.erth.network:443")
    monkeypatch.setattr(config, "EARTH_NODE_URL", "rest+https://lcd.erth.network")
    edge.check()


def test_no_token_sends_nothing(monkeypatch):
    monkeypatch.setattr(config, "CHAIN_EDGE_TOKEN", "")
    assert edge.headers("https://rpc.erth.network:443") == {}
    assert edge.node_flag("https://rpc.erth.network:443") == "https://rpc.erth.network:443"


def test_node_flag_carries_userinfo(token):
    assert edge.node_flag("https://rpc.erth.network:443") == f"https://earth-backend:{TOK}@rpc.erth.network:443"
    assert edge.node_flag("http://node:26657") == "http://node:26657"


@pytest.mark.parametrize("bad", ["short", "x" * 31, "has space" + "x" * 30, "a@b" + "x" * 40, "x" * 129])
def test_malformed_token_is_refused(monkeypatch, bad):
    monkeypatch.setattr(config, "CHAIN_EDGE_TOKEN", bad)
    with pytest.raises(RuntimeError) as e:
        edge.check()
    assert bad not in str(e.value)


def test_missing_token_warns_without_secrets(monkeypatch, caplog):
    monkeypatch.setattr(config, "CHAIN_EDGE_TOKEN", "")
    monkeypatch.setattr(config, "EARTH_RPC_URL", "https://rpc.erth.network:443")
    with caplog.at_level("WARNING", logger="services.edge"):
        edge.check()
    assert "EARTH_RPC_URL" in caplog.text


def test_comet_rpc_sends_the_header(token):
    seen = []

    def handler(request):
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"result": {"ok": True}})

    async def go(url):
        rpc = CometRPC(url, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        await rpc._call("status")
        await rpc.close()

    asyncio.run(go("https://rpc.erth.network:443"))
    asyncio.run(go("https://rpc.example.org"))
    assert seen[0] == edge.header_value() and seen[1] is None


def test_gas_check_gets_the_credentialed_node(token, monkeypatch):
    monkeypatch.setattr(config, "EARTH_RPC_URL", "https://rpc.erth.network:443")
    argv = []

    class Proc:
        returncode = 0

        async def communicate(self, stdin=None):
            return b'{"ok": true}\n', b""

    async def fake_exec(*args, **kwargs):
        argv.extend(args)
        return Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    asyncio.run(gascheck._run(["register"]))
    assert argv[argv.index("--node") + 1] == f"https://earth-backend:{TOK}@rpc.erth.network:443"
