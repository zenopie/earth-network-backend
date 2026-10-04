"""Notes stream format 2: open notes (the referral note the chain mints
with a public opening) and split LP payouts
(one payout leg minted as several notes with the same ciphertext)."""
import base64
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import config
from routers import privacy
from services.privacy import events, store as store_mod, verify
from services.privacy.store import Store
from services.zk import privacy as zp
from tests.privacy_fixtures import ChainClient, seed_chain

OWNER = zp.owner_pk(77)
RHO, RCM = zp.referral_opening(88, 5)
CT = bytes(range(177))


def _ev(t: str, mode: str | None = None, **attrs) -> dict:
    a = [{"key": k, "value": str(v)} for k, v in attrs.items()]
    if mode:
        a.append({"key": "mode", "value": mode})
    return {"type": t, "attributes": a}


def _h(v: int) -> str:
    return v.to_bytes(32, "big").hex()


def _open_note(pos: int, value: int, **over) -> list[dict]:
    """MintOpenNote's events: shielded_note with no ciphertext, then
    shielded_mint with the opening (attributes replaced by over; None drops one)."""
    cm = zp.cm(zp.asset_id("uerth"), value, zp.pc(OWNER, RHO, RCM))
    mint = {"module": "personhood", "amount": f"{value}uerth", "position": pos, "ciphertext": "",
            "owner_pk": _h(OWNER), "rho": _h(RHO), "rcm": _h(RCM), **over}
    return [_ev("shielded_note", position=pos, commitment=_h(cm), ciphertext=""),
            _ev("shielded_mint", **{k: v for k, v in mint.items() if v is not None})]


def _minted(pos: int, value: int, ct: bytes = CT, cm: int | None = None, module="dex", mode=None) -> list[dict]:
    """MintNote's events: a ciphertext note and its mint."""
    b64 = base64.b64encode(ct).decode()
    return [_ev("shielded_note", mode, position=pos, commitment=_h(cm if cm is not None else 1000 + pos),
                ciphertext=b64),
            _ev("shielded_mint", mode, module=module, amount=f"{value}uerth", position=pos, ciphertext=b64)]


def _register(**attrs) -> dict:
    base = {"nullifier": _h(88), "leaf_index": 5, "reward": 10, "switched": "false"}
    return _ev("register", **{**base, **attrs})


def _block(height: int, tx_events: list[dict] = (), finalize: list[dict] = ()) -> dict:
    return {"height": str(height), "txs_results": [{"code": 0, "events": list(tx_events)}] if tx_events else [],
            "finalize_block_events": list(finalize)}


# --- parsing --------------------------------------------------------------

def test_an_open_note_is_parsed_with_its_opening():
    res = _block(5, [*_minted(0, 10, module="personhood"), *_open_note(1, 10),
                     _register(handle="amy", referral=10, referral_position=1)])
    d = events.parse_block(5, 0, "H", res)
    n = d.notes[1]
    assert n.ciphertext == b"" and n.amount == "10uerth"
    assert (n.owner_pk, n.rho, n.rcm) == (bytes.fromhex(_h(OWNER)), bytes.fromhex(_h(RHO)), bytes.fromhex(_h(RCM)))
    assert d.notes[0].owner_pk is None and d.notes[0].ciphertext == CT
    assert [(r.position, r.amount) for r in d.referrals] == [(1, 10)]


@pytest.mark.parametrize("over,match", [
    ({"owner_pk": None}, "owner_pk"),  # part of the opening missing
    ({"rho": None}, "rho"),
    ({"rcm": "ab"}, "rcm"),
    ({"owner_pk": "zz" * 32}, "owner_pk"),
])
def test_a_malformed_opening_is_refused(over, match):
    with pytest.raises(events.EventError, match=match):
        events.parse_block(5, 0, "H", _block(5, _open_note(0, 10, **over)))


def test_an_opening_on_a_note_with_a_ciphertext_is_refused():
    evs = _minted(0, 10)
    evs[1]["attributes"] += [{"key": "owner_pk", "value": _h(OWNER)}, {"key": "rho", "value": _h(RHO)},
                             {"key": "rcm", "value": _h(RCM)}]
    with pytest.raises(events.EventError, match="an opening and a ciphertext"):
        events.parse_block(5, 0, "H", _block(5, evs))


@pytest.mark.parametrize("reg,match", [
    ({"referral_position": 0}, "not an open note"),  # names the registrant's own (ciphertext) note
    ({"referral_position": 7}, "not an open note"),  # no such note in the block
    ({"referral": 11}, "differs"),
])
def test_a_register_referral_must_name_its_open_note(reg, match):
    attrs = {"handle": "amy", "referral": 10, "referral_position": 1, **reg}
    res = _block(5, [*_minted(0, 10, module="personhood"), *_open_note(1, 10), _register(**attrs)])
    with pytest.raises(events.EventError, match=match):
        events.parse_block(5, 0, "H", res)


def test_an_unpaid_referral_names_no_position():
    # A referred registration whose referral half is zero: handle and
    # referral "0", no referral_position, no open note.
    d = events.parse_block(5, 0, "H", _block(5, [*_minted(0, 10, module="personhood"),
                                                  _register(handle="amy", referral=0)]))
    assert d.referrals == [] and all(n.owner_pk is None for n in d.notes)


def test_a_split_lp_payout_indexes_every_note():
    # x/dex MintNoteSplit: a payout leg above 2^64-1 is ceil(v/(2^64-1))
    # notes to the same pc with the same ciphertext, each its own
    # shielded_note + shielded_mint at its own position (EndBlock sweep).
    u64 = 2**64 - 1
    values = [u64, u64, 5]
    fin = [e for i, v in enumerate(values) for e in _minted(i, v, mode="EndBlock")]
    d = events.parse_block(5, 0, "H", _block(5, finalize=fin))
    assert [(n.position, n.amount, n.ciphertext) for n in d.notes] == [
        (0, f"{u64}uerth", CT), (1, f"{u64}uerth", CT), (2, "5uerth", CT)]


# --- the store and the stream ----------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    path = str(tmp_path / "index.db")
    monkeypatch.setattr(config, "INDEX_DB", path)
    monkeypatch.setattr(config, "PRIVACY_PAGE_SIZES", (100, 1000))
    seed_chain(path)
    app = FastAPI()
    app.include_router(privacy.router)

    def apply(*blocks):
        st = Store(path)
        for h, res in blocks:
            assert st.apply(events.parse_block(h, h, f"H{h}", res))
        st.close()

    return path, apply, lambda: ChainClient(TestClient(app))


def _rows(client) -> list[dict]:
    body = client.get("/privacy/notes", params={"from_pos": 0, "limit": 100}).json()
    assert body["format"] == 2
    return [dict(zip(body["fields"], r)) for r in body["notes"]]


def test_a_referral_mint_row_and_a_split_payout_in_the_stream(api):
    path, apply, client = api
    u64 = 2**64 - 1
    ct2 = bytes([9]) * 177
    apply((1, _block(1, [*_minted(0, 10, module="personhood"), *_open_note(1, 10),
                         _register(handle="amy", referral=10, referral_position=1)])),
          (2, _block(2, finalize=[e for i, v in enumerate([u64, u64, 3])
                                  for e in _minted(2 + i, v, ct=ct2, mode="EndBlock")])))
    c = client()
    rows = _rows(c)
    assert [r["position"] for r in rows] == [0, 1, 2, 3, 4]
    # The referral mint: no ciphertext, its opening, enough to match locally.
    ref = rows[1]
    assert ref == {"position": 1, "height": 1, "cm": ref["cm"], "ciphertext": None, "amount": "10uerth",
                   "owner_pk": _h(OWNER), "rho": _h(RHO), "rcm": _h(RCM)}
    assert int(ref["cm"], 16) == zp.cm(zp.asset_id("uerth"), 10, zp.pc(OWNER, RHO, RCM))
    # The split payout: three rows, one ciphertext, each its own amount.
    split = rows[2:]
    assert {r["ciphertext"] for r in split} == {base64.b64encode(ct2).decode()}
    assert [r["amount"] for r in split] == [f"{u64}uerth", f"{u64}uerth", "3uerth"]
    assert all(r["height"] == 2 and r["owner_pk"] is r["rho"] is r["rcm"] is None for r in split)
    assert c.get("/privacy/status").json()["note_format"] == 2


def test_verify_checks_every_open_note_commitment(api):
    path, apply, _ = api
    apply((1, _block(1, _open_note(0, 10))))
    conn = store_mod.connect(path, readonly=True)
    rep = verify.rebuild(conn)
    assert rep.ok and rep.open_notes_checked == 1
    conn.close()
    # An opening that does not open the commitment is reported.
    rw = sqlite3.connect(path)
    rw.execute("UPDATE notes SET rho = ? WHERE position = 0", (bytes(32),))
    rw.commit()
    rw.close()
    conn = store_mod.connect(path, readonly=True)
    rep = verify.rebuild(conn)
    assert any("open note 0" in e for e in rep.errors)
    conn.close()


def test_an_index_from_before_open_notes_is_refused(tmp_path):
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE notes (position INTEGER PRIMARY KEY, cm BLOB NOT NULL, ciphertext BLOB NOT NULL,"
              " height INTEGER NOT NULL, amount TEXT)")
    c.commit()
    c.close()
    with pytest.raises(RuntimeError, match="predates open notes"):
        store_mod.connect(path)
