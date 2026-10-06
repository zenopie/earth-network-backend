"""Building /gas/register requests for tests: a real-looking registration,
the gas router app, proof-of-work stamps and throwaway certificates.

reg_body() is a MsgRegister whose binding, nullifier and DSC commitment agree
the way a real registration's do (dsc_der is a real P-256 DSC, its chain
commitment in public_signals[3]); the gas-check verdict is stood in for by
the fixtures in conftest.py.
"""
import base64
import datetime
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config
from services import pow
from services.zk import privacy
from services.zk.poseidon2 import P


def gas_app():
    """The gas router behind the same body cap main.py installs."""
    from fastapi import FastAPI

    from routers import gas
    from services.bodylimit import BodyLimit

    app = FastAPI()
    app.add_middleware(BodyLimit)
    app.include_router(gas.router)
    return app


# --- a registration -------------------------------------------------------------


B64 = base64.b64encode(b"x").decode()


# A real P-256 DSC certificate (tests/fixtures/dsc) and its chain commitment
# (pinned against x/pki/certs.DscCommitmentOf in test_gas_reserved_lane): reg_body's
# dsc_der and public_signals[3] agree, as a real registration's do.
_DSC_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dsc")


DSC_DER = open(os.path.join(_DSC_DIR, "dsc_p256.der"), "rb").read()


DSC_DER_B64 = base64.b64encode(DSC_DER).decode()


DSC_KEY = int("304606d727af8b6715f57c615779a33f1b00c00a1c5f50b7dd704b57a62ace59", 16)


NF = int("aa" * 32, 16) % P


NF_HEX = privacy.field_bytes(NF).hex()


def field_b64(v: int) -> str:
    return base64.b64encode(v.to_bytes(32, "big")).decode()


def today_yymmdd(offset_days: int = 0) -> int:
    t = time.gmtime(time.time() + offset_days * 86400)
    return (t.tm_year % 100) * 10000 + t.tm_mon * 100 + t.tm_mday


PC_GAS = (0x1234).to_bytes(32, "big")


# Amount-blind v2 ciphertexts: exactly 177 bytes each.
CT_ANML, CT_ERTH, CT_GAS = bytes([1]) * 177, bytes([2]) * 177, bytes([3]) * 177


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# A referral: a live handle (MsgRegister affiliate_handle 15). OLD_PC / OLD_CT
# fill affiliate_pc / affiliate_ciphertext, which are not MsgRegister fields
# and must be refused.
REFERRAL = {"affiliate_handle": "amy-2"}


OLD_PC, OLD_CT = base64.b64encode((0x5678).to_bytes(32, "big")).decode(), base64.b64encode(bytes([4]) * 177).decode()


def affiliate_of(over: dict) -> int:
    """The binding's affiliate field for a body's referral (0 for none)."""
    return privacy.affiliate_field(over["affiliate_handle"]) if over.get("affiliate_handle") else 0


def signals(nf: int = NF, date: int | None = None, idc=11, pc_anml=12, pc_erth=13, aff: int = 0,
            ct_anml: bytes = CT_ANML, ct_erth: bytes = CT_ERTH) -> list[str]:
    """[current_date, binding, nullifier, dsc_key, idc], the earth-1 lean_poa layout."""
    binding = privacy.registration_binding(config.EARTH_CHAIN_ID, idc, pc_anml, ct_anml, pc_erth, ct_erth, aff)
    return [str(today_yymmdd() if date is None else date), str(binding), str(nf), str(DSC_KEY), str(idc)]


def reg_body(gas_pc: bytes = PC_GAS, nf: int = NF, **over):
    body = {"proof": B64, "public_signals": signals(nf, aff=affiliate_of(over)),
            "signature_algorithm": "lean_poa", "dsc_der": DSC_DER_B64,
            "idc": field_b64(11), "pc_anml": field_b64(12), "pc_erth": field_b64(13),
            "ciphertext_anml": b64(CT_ANML), "ciphertext_erth": b64(CT_ERTH),
            "pc_gas": base64.b64encode(gas_pc).decode(), "ciphertext_gas": b64(CT_GAS)}
    body.update(over)
    return body




# --- proof of work ----------------------------------------------------------------


def with_pow(body: dict, bits: int) -> dict:
    """body with a proof-of-work stamp of at least `bits` (services/pow)."""
    ts = int(time.time())
    sig = body["public_signals"]
    nonce = pow.solve(ts, sig[config.PASSPORT_ADDRESS_INDEX], sig[config.PASSPORT_NULLIFIER_INDEX], bits)
    return dict(body, pow={"ts": ts, "nonce": nonce})


def weak_pow(body: dict, below: int) -> dict:
    """body with a well-formed stamp of fewer than `below` bits."""
    import hashlib

    ts = int(time.time())
    sig = body["public_signals"]
    for i in range(1000):
        d = hashlib.sha256(pow.stamp_input(ts, sig[config.PASSPORT_ADDRESS_INDEX], sig[config.PASSPORT_NULLIFIER_INDEX], str(i))).digest()
        if pow.leading_zero_bits(d) < below:
            return dict(body, pow={"ts": ts, "nonce": str(i)})
    raise AssertionError("unreachable")


def pow_between(b: dict, lo: int, hi: int) -> dict:
    """b with a stamp of at least lo and fewer than hi bits (a with_pow stamp
    can happen to clear hi as well)."""
    import hashlib
    import time

    from services import pow

    ts = int(time.time())
    sig = b["public_signals"]
    for i in range(1 << 20):
        d = hashlib.sha256(pow.stamp_input(ts, sig[config.PASSPORT_ADDRESS_INDEX],
                                           sig[config.PASSPORT_NULLIFIER_INDEX], str(i))).digest()
        if lo <= pow.leading_zero_bits(d) < hi:
            return dict(b, pow={"ts": ts, "nonce": str(i)})
    raise AssertionError("unreachable")




# --- requests from many clients, under many signers --------------------------------


def dsc_cert(country: str) -> str:
    """A throwaway certificate whose issuer is C=<country>, base64 DER."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                      x509.NameAttribute(NameOID.COMMON_NAME, "test DSC")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


DE, FR = dsc_cert("DE"), dsc_cert("FR")


def body(nf: int, dsc: int = DSC_KEY, der: str | None = None) -> dict:
    b = reg_body(nf=nf)
    s = signals(nf)
    s[3] = str(dsc)
    b["public_signals"] = s
    if der is not None:
        b["dsc_der"] = der
    return b


_ip = iter(range(1, 10**6))


def post_as(client, b, ip):
    """Posts b from client address ip (CF-Connecting-IP, trusted under the chain fixture)."""
    return client.post("/gas/register", json=b, headers={"cf-connecting-ip": ip})


def post(client, b):
    i = next(_ip)
    return client.post("/gas/register", json=b, headers={"cf-connecting-ip": f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}"})


PROOF = "invalid registration proof"


NOT_CHAINED = "no trusted issuing CSCA found"


COUNTRY_CAP = "country DE has reached its 100 registrations for today; retry tomorrow: " \
              "daily registration limit reached for this document signer or country"


RATE_CAP = "dsc 0a: daily registration limit reached for this document signer or country"


CHEAP_REFUSALS = [
    "no trusted issuing CSCA found",
    "proof is not bound to the supplied DSC: proof public inputs do not match",
    'affiliate_handle "amy": affiliate_handle is not a live handle',
    "invalid certificate",
]




# --- certificates -------------------------------------------------------------------


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def rsa_cert(modulus_bytes: int, salt: bytes = b"\x01") -> str:
    """A certificate shell (unsigned) around a random RSA modulus of that many bytes."""
    modulus = b"\x7f" + os.urandom(modulus_bytes - 1)
    rsakey = _der(0x30, _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01"))
    spki = _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
                + _der(0x03, b"\x00" + rsakey))
    tbs = _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + _der(0x02, salt) + _der(0x30, b"") * 4 + spki)
    return base64.b64encode(_der(0x30, tbs + _der(0x30, b"") + _der(0x03, b"\x00"))).decode()


def expired_cert() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")])
    t = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(t).not_valid_after(t + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
