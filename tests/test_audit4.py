"""Audit round 4 (backend): regressions for each finding.

B5: _yymmdd_unix took Feb 31 as Mar 3 (Go's time.Date normalisation); the
chain's yymmddToUnix now refuses a date that does not round-trip, so must we.
"""
import pytest

from routers import gas


@pytest.mark.parametrize("v", [250231, 250230, 250431, 230229, 251131])
def test_impossible_dates_are_refused_like_the_chain(v):
    with pytest.raises(ValueError, match="calendar date"):
        gas._yymmdd_unix(v)


def test_real_dates_still_parse():
    assert gas._yymmdd_unix(240229) == 1709164800  # 2024 is a leap year
    assert gas._yymmdd_unix(250101) == 1735689600
    assert gas._yymmdd_unix(251231) == 1767139200


# --- B2: a non-200 answer after the node took the tx -------------------------
#
# poc test_poc_nonok_http_double_grant.py: cosmpy's REST client raises a bare
# RuntimeError for any non-200 answer. Behind Cloudflare a 524 can arrive
# after the node accepted the tx; _broadcast took it for "moved nothing",
# _grant_note released the passport and the retry was paid again.

from cosmpy.aerial.exceptions import BroadcastError  # noqa: E402

from services import chain as chain_mod  # noqa: E402
from tests.test_chain import SIGNED_HASH, _send_with  # noqa: E402
from tests.test_proof_grants import chain_says, reg_body  # noqa: E402,F401

CF_524 = RuntimeError("Error when sending a POST request.\n Request: {...}\n Response: 524, b'error code: 524'")


def test_a_non_200_after_accept_is_resolved_by_hash(monkeypatch):
    assert _send_with(monkeypatch, CF_524, landed=True) == SIGNED_HASH


def test_a_non_200_never_seen_is_unresolved(monkeypatch):
    with pytest.raises(chain_mod.SendUnresolved) as info:
        _send_with(monkeypatch, CF_524)
    assert info.value.tx_hash == SIGNED_HASH


def test_checktx_refusal_moved_nothing(monkeypatch):
    with pytest.raises(BroadcastError):
        _send_with(monkeypatch, BroadcastError("H", "insufficient fees"))


def test_already_in_mempool_is_resolved_by_hash(monkeypatch):
    exc = BroadcastError("H", "tx already exists in cache")
    assert _send_with(monkeypatch, exc, landed=True) == SIGNED_HASH


def _cf524_broadcast(monkeypatch, landed_after_first: bool):
    """chain internals stubbed: the first broadcast raises a 524 after the tx
    reached the mempool (it lands); later ones succeed."""
    import asyncio

    from routers import gas

    sent = []

    class Tx:
        tx = type("T", (), {"SerializeToString": lambda self: b"signed%d" % len(sent)})()

    class Client:
        def broadcast_tx(self, tx):
            sent.append(tx)
            if len(sent) == 1:
                raise CF_524
            return chain_mod.SubmittedTx(self, chain_mod.tx_hash_of(tx))

    def waited(self, *a, **k):
        if not landed_after_first:
            raise chain_mod.QueryTimeoutError()
        return self

    class _W:
        def address(self):
            return "earth1x"

    monkeypatch.setattr(chain_mod, "Transaction", lambda: type("B", (), {"add_message": lambda self, m: None, "tx": Tx.tx})())
    monkeypatch.setattr(chain_mod, "prepare_basic_transaction", lambda *a, **k: None)
    monkeypatch.setattr(chain_mod.shielded_msg, "build", lambda *a, **k: None)
    monkeypatch.setattr(chain_mod.SubmittedTx, "wait_to_complete", waited)
    monkeypatch.setattr(chain_mod, "_client", Client())
    monkeypatch.setattr(chain_mod, "_wallet", _W())
    monkeypatch.setattr(chain_mod, "_send_lock", asyncio.Lock())
    assert gas.chain is chain_mod
    return sent


def test_the_passport_is_paid_once(client, chain_says, monkeypatch):
    sent = _cf524_broadcast(monkeypatch, landed_after_first=True)
    r1 = client.post("/gas/register", json=reg_body())
    assert r1.status_code == 200, r1.text
    r2 = client.post("/gas/register", json=reg_body())
    assert r2.status_code == 409
    assert len(sent) == 1


def test_an_unseen_524_keeps_the_passport_claimed(client, chain_says, monkeypatch):
    sent = _cf524_broadcast(monkeypatch, landed_after_first=False)
    r1 = client.post("/gas/register", json=reg_body())
    assert r1.status_code == 202 and r1.json()["tx_hash"]
    assert client.post("/gas/register", json=reg_body()).status_code == 409
    assert len(sent) == 1
