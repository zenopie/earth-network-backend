"""Real attestation chains, from Google's android-key-attestation test resources.

The synthetic chains in conftest prove the checks; these prove the parser
survives what phones actually emit. Both come from a device with an unlocked
bootloader, attesting the challenge b"abc".
"""
import os

import pytest

from services import keyattest

HERE = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name: str) -> list[bytes]:
    return [open(os.path.join(HERE, name, f"cert{i}.der"), "rb").read() for i in range(4)]


def app_id(chain):
    desc = keyattest._key_description(keyattest._Cert(chain[0]).key_description)
    return keyattest._application_id(desc["software"].get(709) or desc["hardware"][709])


def test_real_tee_chain_verifies_against_google_roots():
    chain = load("algorithm_EC_SecurityLevel_TEE")
    packages, digests = app_id(chain)
    keyattest.verify(chain, b"abc", package=sorted(packages)[0], signing_digests=digests,
                     revoked=set(), require_locked=False)


def test_real_tee_chain_is_refused_with_its_unlocked_bootloader():
    chain = load("algorithm_EC_SecurityLevel_TEE")
    packages, digests = app_id(chain)
    with pytest.raises(keyattest.AttestationError, match="unlocked"):
        keyattest.verify(chain, b"abc", package=sorted(packages)[0], signing_digests=digests, revoked=set())


def test_non_strict_der_leaf_parses():
    # This StrongBox leaf writes ecdsa-with-SHA256 with an explicit NULL
    # parameter, which `cryptography` refuses to load at all.
    chain = [keyattest._Cert(c) for c in load("algorithm_EC_SecurityLevel_StrongBox")]
    assert all(c.signed_by(i) for c, i in zip(chain, chain[1:]))
    assert keyattest._key_description(chain[0].key_description)["attestation_security_level"] == 2
