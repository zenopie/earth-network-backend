import base64
import hashlib
import importlib
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# --- ASN.1 and Crypto Libraries ---
import asn1crypto.cms as cms
import asn1crypto.algos as algos
import asn1crypto.core as core
import asn1crypto.x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from pymrtd.ef.sod import SOD as PymrtdSOD

# Module-level holders populated by the pytest fixture so tests can reuse the
# same CSCA and DS key/certificate used by the temporary trust store.
TEST_CSCA_CERT = None
TEST_CSCA_KEY = None
TEST_DS_CERT = None
TEST_DS_KEY = None

# --- Import Application Modules ---
# It's important that these are imported so they can be patched/reloaded later.
import config
from routers import verify as verify_module


# --------------------------------------------------------------------------
# 1. Test Public Key Infrastructure (PKI) Generation
#
# Generates a root Country Signing CA (CSCA) and a Document Signer (DS)
# certificate, signed by the CSCA.
# --------------------------------------------------------------------------
def generate_test_pki():
    """Generates a consistent CSCA and a DS certificate/key pair for testing."""
    # CSCA (The Root of Trust)
    csca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"UT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UnitTest CSCA"),
    ])
    csca_cert = (
        x509.CertificateBuilder()
        .subject_name(csca_subject)
        .issuer_name(csca_subject)
        .public_key(csca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(csca_key, hashes.SHA256())
    )

    # Document Signer (DS) Certificate (signed by CSCA)
    ds_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ds_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"UT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UnitTest DS"),
    ])
    ds_cert = (
        x509.CertificateBuilder()
        .subject_name(ds_subject)
        .issuer_name(csca_subject)  # Issued by the CSCA
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(csca_key, hashes.SHA256()) # Signed by the CSCA's private key
    )

    return csca_cert, csca_key, ds_cert, ds_key

# --------------------------------------------------------------------------
# 2. DG1 and SOD Generation
#
# Creates a valid ePassport Security Object Document (SOD) containing a
# hash of a dummy Data Group 1 (DG1).
# --------------------------------------------------------------------------

def _crypto_name_to_asn1_dict(name):
    """Helper to convert cryptography.x509.Name to a dict for asn1crypto."""
    mapping = {
        NameOID.COUNTRY_NAME: 'country_name',
        NameOID.STATE_OR_PROVINCE_NAME: 'state_or_province_name',
        NameOID.LOCALITY_NAME: 'locality_name',
        NameOID.ORGANIZATION_NAME: 'organization_name',
        NameOID.ORGANIZATIONAL_UNIT_NAME: 'organizational_unit_name',
        NameOID.COMMON_NAME: 'common_name',
        NameOID.SERIAL_NUMBER: 'serial_number',
    }
    d = {}
    for attr in name:
        key = mapping.get(attr.oid)
        if key:
            d[key] = attr.value
    return d

def generate_dg1_sod(ds_cert, ds_key):
    """Generates Base64 encoded DG1 and a correctly structured SOD."""
    # Create dummy DG1 from a Machine Readable Zone (MRZ) string
    mrz = "P<UTOERTHNETWORK<<TESTER<<<<<<<<<<<<<<<<<<<<<\n1234567890UTO8001019M2501012<<<<<<<<<<<<<<08"
    dg1_bytes = mrz.encode()
    dg1_b64 = base64.b64encode(dg1_bytes).decode()
    dg1_hash = hashlib.sha256(dg1_bytes).digest()

    # --- Step 1: Build the inner content (LDSecurityObject) ---
    # This object contains the hashes of the Data Groups.
    # Use the LDSSecurityObject/DataGroupHash types from pymrtd so the resulting
    # object is compatible with the SOD parser/verifier.
    from pymrtd.ef.sod import LDSSecurityObject as PymrtdLDSSecurityObject  # type: ignore
    # Build the LDSSecurityObject using the field names expected by pymrtd
    lds_obj = PymrtdLDSSecurityObject({
        'version': 0,
        'hashAlgorithm': {'algorithm': 'sha256'},
        'dataGroupHashValues': [{'dataGroupNumber': 1, 'dataGroupHashValue': dg1_hash}]
    })
    content_der = lds_obj.dump()

    # --- Step 2: Build the CMS SignedAttributes ---
    # These attributes are what actually get signed in a CMS structure.
    # Use the ICAO OID expected by pymrtd for LDS Security Object
    content_oid = '2.23.136.1.1.1'  # id_mrtd_ldsSecurityObject (ICAO)
    content_digest = hashlib.sha256(content_der).digest()
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({'type': 'content_type', 'values': [cms.ContentType(content_oid)]}),
        cms.CMSAttribute({'type': 'message_digest', 'values': [content_digest]})
    ])
    
    # Sign the DER-encoded representation of the attributes.
    signed_attrs_der = signed_attrs.dump()
    signature = ds_key.sign(signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())

    # --- Step 3: Build the SignerInfo ---
    # This structure links the signature to the signer's certificate.
    # **FIX:** Use the certificate's ISSUER and serial number to identify it.
    signer_info = cms.SignerInfo({
        'version': 1,
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': asn1_x509.Name.build(_crypto_name_to_asn1_dict(ds_cert.issuer)),
                'serial_number': ds_cert.serial_number
            })
        }),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature
    })

    # --- Step 4: Assemble the final CMS SignedData structure ---
    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {'content_type': content_oid, 'content': lds_obj},
        'certificates': [asn1_x509.Certificate.load(ds_cert.public_bytes(serialization.Encoding.DER))],
        'signer_infos': [signer_info]
    })
    content_info = cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})
    content_info_der = content_info.dump()

    # --- Step 5: Wrap the CMS structure in the EF.SOD file format ---
    # Use the EF.SOD tag expected by pymrtd (23).
    sod_obj = PymrtdSOD(tag=23, contents=content_info_der)
    sod_der = sod_obj.dump()
    sod_b64 = base64.b64encode(sod_der).decode()

    return dg1_b64, sod_b64

# --------------------------------------------------------------------------
# 3. Pytest Fixture for Test Client
#
# Sets up a temporary trust store and a FastAPI test client.
# --------------------------------------------------------------------------
@pytest.fixture
def client():
    """A pytest fixture that provides a configured FastAPI TestClient."""
    # Generate a CSCA and DS for this test run and store module-level refs
    global TEST_CSCA_CERT, TEST_CSCA_KEY, TEST_DS_CERT, TEST_DS_KEY
    csca_cert, csca_key, ds_cert, ds_key = generate_test_pki()
    TEST_CSCA_CERT = csca_cert
    TEST_CSCA_KEY = csca_key
    TEST_DS_CERT = ds_cert
    TEST_DS_KEY = ds_key

    with tempfile.TemporaryDirectory() as tmp_dir_name:
        csca_dir = Path(tmp_dir_name)
        
        # Write the trusted CSCA cert to the temporary directory
        csca_path = csca_dir / "test_csca.der"
        csca_path.write_bytes(csca_cert.public_bytes(serialization.Encoding.DER))

        # Patch the config to point to our temporary trust store
        config.CSCA_DIR = str(csca_dir)

        # Reload the verify module to force it to load our new CSCA certificate
        # This is crucial because the certs are loaded at module import time.
        importlib.reload(verify_module)

        # Create and configure the FastAPI app for testing
        app = FastAPI()
        app.include_router(verify_module.router, prefix="/api")
        
        with TestClient(app) as test_client:
            yield test_client

# --------------------------------------------------------------------------
# 4. End-to-End Test Function
# --------------------------------------------------------------------------
def test_verify_endpoint_with_valid_data(client):
    """Tests the /verify endpoint with a correctly generated and signed SOD."""
    # Use the DS cert/key produced by the fixture (signed by the CSCA in the fixture's trust store)
    ds_cert = TEST_DS_CERT
    ds_key = TEST_DS_KEY

    # Generate the DG1 and SOD using the valid DS certificate and key
    dg1_b64, sod_b64 = generate_dg1_sod(ds_cert, ds_key)

    # Make the API call
    response = client.post("/api/verify", json={"dg1": dg1_b64, "sod": sod_b64})

    # Print debug information
    print(f"Response Status Code: {response.status_code}")
    try:
        response_json = response.json()
        print("Response JSON:", response_json)
        # Extract and print the final result for quick validation
        print("--> Passive Authentication Passed:", response_json.get("passive_authentication_passed"))
    except Exception:
        print("Response Text:", response.text)

    # Assertions: Verify the outcome
    assert response.status_code == 200
    data = response.json()
    assert data["passive_authentication_passed"] is True
    assert data["details"]["trust_chain"]["status"] == "VALID"
    assert data["details"]["sod_signature"]["status"] == "VALID"
    assert data["details"]["dg1_hash_integrity"]["status"] == "VALID"