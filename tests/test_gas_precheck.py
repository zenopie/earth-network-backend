"""/gas/register's checks before gas-check: shape and bounds
(MsgRegister.ValidateBasic), the registration binding, the referral, the
proof's date and the document signer's validity. Each is refused 400 (422
for the schema) without asking gas-check.
"""
import base64

import pytest
from cryptography import x509

from routers import gas
from services import ratelimit
from services.zk.poseidon2 import P
from tests.gas_fixtures import (B64, CT_ANML, CT_ERTH, CT_GAS, OLD_CT, OLD_PC, REFERRAL, affiliate_of, b64, body,
                                expired_cert, field_b64, post_as, reg_body, signals, today_yymmdd)


@pytest.mark.parametrize("over", [
    {"proof": "not base64!"},
    {"pc_gas": base64.b64encode(b"\x01" * 31).decode()},
    {"pc_gas": base64.b64encode(P.to_bytes(32, "big")).decode()},  # not canonical
    {"idc": B64},
    {"ciphertext_gas": base64.b64encode(b"\x00" * 1025).decode()},
    {"ciphertext_gas": ""},  # required
    {"ciphertext_gas": b64(CT_GAS[:-1])},  # not exactly 177
    {"ciphertext_gas": b64(CT_GAS + b"\x00")},
    {"ciphertext_anml": ""},
    {"ciphertext_erth": b64(CT_ERTH[:-1])},
    # Not a handle: case, length, characters, edge dashes.
    {**REFERRAL, "affiliate_handle": "Amy"},
    {**REFERRAL, "affiliate_handle": "am"},
    {**REFERRAL, "affiliate_handle": "a" * 33},
    {**REFERRAL, "affiliate_handle": "-amy"},
    {**REFERRAL, "affiliate_handle": "amy-"},
    {**REFERRAL, "affiliate_handle": "amy_2"},
    {**REFERRAL, "affiliate_handle": "earth1s7rgscltvw8v3kzhj46pptdqg843ngs7th9ywp"},  # an address, not a handle
])
def test_register_rejects_malformed_fields_before_asking(client, shields, chain_says, over):
    assert client.post("/gas/register", json=reg_body(**over)).status_code == 400
    assert chain_says["asked"] == []


@pytest.mark.parametrize("over", [
    {"proof": ""},
    {"dsc_der": ""},
    {"dsc_der": base64.b64encode(b"\x00" * (8 * 1024 + 1)).decode()},
    {"ciphertext_anml": base64.b64encode(b"\x00" * 1025).decode()},
    {"signature_algorithm": ""},
])
def test_out_of_bounds_fields_are_refused_before_asking(client, shields, chain_says, over):
    assert client.post("/gas/register", json=reg_body(**over)).status_code == 400
    assert chain_says["asked"] == []


@pytest.mark.parametrize("field", ["ciphertext_anml", "ciphertext_erth", "ciphertext_gas"])
def test_every_ciphertext_is_required(client, shields, chain_says, field):
    body = reg_body()
    del body[field]
    assert client.post("/gas/register", json=body).status_code == 422
    assert chain_says["asked"] == []


@pytest.mark.parametrize("sigs", [
    lambda s: s[:2],               # too few for nullifier_index 2
    lambda s: s[:4],               # too few for idc_index 4
    lambda s: s + ["0"] * 12,      # 17 > 16
    lambda s: [],
    lambda s: s[:3] + ["0x07"],    # not decimal
    lambda s: s[:3] + ["+7"],
    lambda s: s[:3] + [str(P)],    # not canonical
])
def test_bad_public_signals_are_refused_before_asking(client, shields, chain_says, sigs):
    body = reg_body()
    body["public_signals"] = sigs(body["public_signals"])
    assert client.post("/gas/register", json=body).status_code == 400
    assert chain_says["asked"] == []


@pytest.mark.parametrize("over", [
    {"pc_erth": field_b64(99)},  # proof made for other notes
    {"idc": field_b64(99)},
    # same notes, other ciphertexts: the binding covers Bytes(ct_anml), Bytes(ct_erth)
    {"ciphertext_anml": b64(bytes([9]) * 177)},
    {"ciphertext_erth": b64(CT_ANML)},
])
def test_a_proof_bound_to_other_notes_is_refused_before_asking(client, shields, chain_says, over):
    resp = client.post("/gas/register", json=reg_body(**over))
    assert resp.status_code == 400 and "bound" in resp.json()["message"]
    assert chain_says["asked"] == []


@pytest.mark.parametrize("idc_signal", [
    "99",                     # an identity whose secret the prover holds, not the one named
    "0",
    str(11 + 2 ** 128),
])
def test_a_proof_of_another_identity_is_refused_before_asking(client, shields, chain_says, idc_signal):
    # The binding commits to idc 11 (a seller naming a buyer's identity), but
    # the circuit's idc output is H(TAG_ID, id_secret) of the prover's own
    # secret: the chain refuses the mismatch (1103), so this backend does too.
    body = reg_body()
    body["public_signals"][4] = idc_signal
    resp = client.post("/gas/register", json=body)
    assert resp.status_code == 400 and "identity commitment" in resp.json()["message"]
    assert chain_says["asked"] == []


def test_the_idc_signal_is_read_at_the_configured_index(client, shields, chain_says, monkeypatch):
    import config
    body = reg_body()
    body["public_signals"] = body["public_signals"][:4] + ["7", body["public_signals"][4]]
    assert client.post("/gas/register", json=body).status_code == 400
    monkeypatch.setattr(config, "PASSPORT_IDC_INDEX", 5)
    assert client.post("/gas/register", json=body).status_code == 200


@pytest.mark.parametrize("swap", [
    {},  # the referral dropped
    {"affiliate_handle": "amy-3"},  # another handle
])
def test_the_referral_is_part_of_the_binding(client, shields, chain_says, swap):
    # A proof bound to REFERRAL, sent with the referral dropped or its handle
    # swapped (a relayer redirecting the referral), is bound to nothing here.
    body = reg_body(nf=2, **(REFERRAL if swap else {}))
    body.update(swap)
    body["public_signals"] = signals(2, aff=affiliate_of(REFERRAL))
    resp = client.post("/gas/register", json=body)
    assert resp.status_code == 400 and "bound" in resp.json()["message"]
    assert chain_says["asked"] == []


def test_a_proof_bound_to_the_old_affiliate_field_is_refused(client, shields, chain_says):
    # An affiliate field over the handle, a pc and a ciphertext,
    # H(tag, Bytes(handle), pc, Bytes(ct)), is not the binding.
    from services.zk.privacy import H, TAG_AFFILIATE, bytes_field
    old = H(TAG_AFFILIATE, bytes_field(b"amy-2"), 0x5678, bytes_field(bytes([4]) * 177))
    body = reg_body(nf=2, **REFERRAL)
    body["public_signals"] = signals(2, aff=old)
    resp = client.post("/gas/register", json=body)
    assert resp.status_code == 400 and "bound" in resp.json()["message"]


@pytest.mark.parametrize("old,named", [
    ({"affiliate_pc": OLD_PC, "affiliate_ciphertext": OLD_CT}, "affiliate_pc and affiliate_ciphertext are"),
    ({"affiliate_pc": OLD_PC}, "affiliate_pc is"),
    ({"affiliate_ciphertext": OLD_CT}, "affiliate_ciphertext is"),
    ({"affiliate_pc": ""}, "affiliate_pc is"),  # present, even empty
])
@pytest.mark.parametrize("referral", [True, False])
def test_the_removed_referral_note_fields_are_a_clear_400(client, shields, chain_says, old, named, referral):
    # A wallet that sends referral note fields is told so, never has them
    # silently dropped.
    body = reg_body(**(REFERRAL if referral else {}))
    body.update(old)
    resp = client.post("/gas/register", json=body)
    assert resp.status_code == 400
    msg = resp.json()["message"]
    assert named in msg and "no longer part of MsgRegister" in msg and "affiliate_handle only" in msg
    assert chain_says["asked"] == [] and shields == []


def test_the_removed_fields_are_not_in_the_published_schema(client):
    props = client.get("/openapi.json").json()["paths"]["/gas/register"]["post"]["requestBody"]["content"][
        "application/json"]["schema"]["properties"]
    assert "affiliate_handle" in props
    assert "affiliate_pc" not in props and "affiliate_ciphertext" not in props


# +4, not +3: a date is 00:00 UTC, so late in a UTC day today+3 is only just
# over 2 days ahead, inside the 2-day skew plus slack, and was accepted.
@pytest.mark.parametrize("date", [today_yymmdd(-3), today_yymmdd(4), 261332, 260100, 1000000])
def test_a_stale_or_malformed_date_is_refused_before_asking(client, shields, chain_says, date):
    body = reg_body()
    body["public_signals"][0] = str(date)
    assert client.post("/gas/register", json=body).status_code == 400
    assert chain_says["asked"] == []


def test_yesterdays_date_is_within_the_skew(client, shields, chain_says):
    body = reg_body()
    body["public_signals"][0] = str(today_yymmdd(-1))
    assert client.post("/gas/register", json=body).status_code == 200


@pytest.mark.parametrize("v", [250231, 250230, 250431, 230229, 251131])
def test_impossible_dates_are_refused_like_the_chain(v):
    with pytest.raises(ValueError, match="calendar date"):
        gas._yymmdd_unix(v)


def test_real_dates_still_parse():
    assert gas._yymmdd_unix(240229) == 1709164800  # 2024 is a leap year
    assert gas._yymmdd_unix(250101) == 1735689600
    assert gas._yymmdd_unix(251231) == 1767139200


def test_an_expired_document_signer_is_refused_before_the_queue(client, chain):
    expired = expired_cert()
    asked = len(chain["priority"])
    for i in range(5):
        r = post_as(client, body(7500 + i, der=expired), "100.64.0.5")
        assert r.status_code == 400 and "expired" in r.json()["message"]
    assert len(chain["priority"]) == asked, "no gas-check"
    assert not ratelimit.client_refused_out(ratelimit.refusal_key("100.64.0.5"))


def test_dsc_expiry_leaves_the_edges_to_the_chain():
    der = base64.b64decode(expired_cert())
    after = x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp()
    assert not gas._dsc_expired(der, now=after + gas._DATE_SLACK_SECONDS - 1)
    assert gas._dsc_expired(der, now=after + gas._DATE_SLACK_SECONDS + 1)
    assert not gas._dsc_expired(b"not a certificate")
