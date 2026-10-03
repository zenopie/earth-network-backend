"""The chain client's transport: bounded requests, and which faults may be retried."""
import hashlib
import socket
import threading
import time

import pytest
import requests
from cosmpy.aerial.client import LedgerClient
from cosmpy.aerial.exceptions import BroadcastError, QueryTimeoutError
from cosmpy.aerial.tx import SigningCfg, Transaction, TxFee
from cosmpy.aerial.wallet import LocalWallet
from cosmpy.crypto.keypairs import PrivateKey

import config
from services import chain, shielded_msg

CT = bytes(range(177))


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


class _Wallet:
    def address(self):
        return "earth1x"


def _send_with(monkeypatch, exc, landed=None):
    """Broadcast raises exc; the chain then shows the tx as `landed`: None
    (never seen), True (succeeded) or False (included and failed)."""
    class Tx:
        tx = type("T", (), {"SerializeToString": lambda self: b"signed"})()

    class Client:
        def broadcast_tx(self, tx):
            raise exc

    def waited(self, *a, **k):
        if landed is None:
            raise QueryTimeoutError()
        if landed is False:
            raise BroadcastError(self.tx_hash, "out of gas")
        return self

    monkeypatch.setattr(chain, "Transaction", lambda: type("B", (), {"add_message": lambda self, m: None, "tx": Tx.tx})())
    monkeypatch.setattr(chain, "prepare_basic_transaction", lambda *a, **k: None)
    monkeypatch.setattr(chain.SubmittedTx, "wait_to_complete", waited)
    monkeypatch.setattr(chain, "_client", Client())
    monkeypatch.setattr(chain, "_wallet", _Wallet())
    return chain._shield_blocking(b"\x07" * 32, CT)


SIGNED_HASH = hashlib.sha256(b"signed").hexdigest().upper()


def test_a_read_timeout_on_broadcast_is_unresolved_with_the_hash(monkeypatch):
    # The node may have accepted the tx before the response was lost; the
    # hash was computed before the post, so the caller still has it.
    with pytest.raises(chain.SendUnresolved) as info:
        _send_with(monkeypatch, requests.exceptions.ReadTimeout())
    assert info.value.tx_hash == SIGNED_HASH


def test_a_lost_response_for_a_tx_that_landed_is_a_success(monkeypatch):
    assert _send_with(monkeypatch, requests.exceptions.ReadTimeout(), landed=True) == SIGNED_HASH


def test_a_lost_response_for_a_tx_that_failed_is_an_ordinary_failure(monkeypatch):
    with pytest.raises(BroadcastError):
        _send_with(monkeypatch, requests.exceptions.ReadTimeout(), landed=False)


def test_a_failure_before_broadcast_is_an_ordinary_failure(monkeypatch):
    # Account lookup or simulation timing out: nothing was posted.
    def slow(*a, **k):
        raise requests.exceptions.ReadTimeout()

    monkeypatch.setattr(chain, "prepare_basic_transaction", slow)
    monkeypatch.setattr(chain, "_client", object())
    monkeypatch.setattr(chain, "_wallet", _Wallet())
    with pytest.raises(requests.exceptions.ReadTimeout) as info:
        chain._shield_blocking(b"\x07" * 32, CT)
    assert not isinstance(info.value, chain.SendUnresolved)


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
    with pytest.raises(chain.SendUnresolved) as info:
        _send_with(monkeypatch, requests.exceptions.ConnectionError("Connection reset by peer"))
    assert info.value.tx_hash == SIGNED_HASH


def _sign(tx, wallet):
    tx.seal(SigningCfg.direct(wallet.public_key(), 0), fee=TxFee([], 0))
    tx.sign(wallet.signer(), "earth-1", 0)
    tx.complete()


def test_the_hash_is_the_chains():
    wallet = LocalWallet(PrivateKey(b"\x01" * 32), prefix="earth")
    tx = Transaction()
    tx.add_message(shielded_msg.build(str(wallet.address()), 1, "uerth", b"\x07" * 32, CT))
    _sign(tx, wallet)
    # CometBFT: a tx is known by the SHA-256 of its bytes, upper-case hex.
    assert chain.tx_hash_of(tx) == hashlib.sha256(tx.tx.SerializeToString()).hexdigest().upper()
    assert len(chain.tx_hash_of(tx)) == 64


def test_shield_builds_msg_shield_from_the_hot_wallet(monkeypatch):
    wallet = LocalWallet(PrivateKey(b"\x01" * 32), prefix="earth")
    seen = {}

    class Submitted:
        tx_hash = "ABC"

        def wait_to_complete(self):
            return None

    def fake_prepare(client, tx, sender):
        seen["msgs"] = tx.msgs
        seen["sender"] = sender
        _sign(tx, sender)

    class Client:
        def broadcast_tx(self, tx):
            return Submitted()

    monkeypatch.setattr(chain, "prepare_basic_transaction", fake_prepare)
    monkeypatch.setattr(chain, "_client", Client())
    monkeypatch.setattr(chain, "_wallet", wallet)
    assert chain._shield_blocking(b"\x07" * 32, CT) == "ABC"
    (msg,) = seen["msgs"]
    assert isinstance(msg, shielded_msg.MsgShield)
    assert msg.sender == str(wallet.address())
    assert (msg.amount.denom, msg.amount.amount) == (config.EARTH_DENOM, str(config.DUST_UERTH))
    assert msg.pc == b"\x07" * 32 and msg.ciphertext == CT
