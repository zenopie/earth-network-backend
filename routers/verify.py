# /routers/verify.py
"""
SOD verification using pymrtd with full trust chain validation.

This implementation performs ePassport Passive Authentication by:
1.  Loading a trust store of Country Signing CA (CSCA) certificates from the
    directory specified in config.CSCA_DIR.
2.  Parsing the ePassport's Security Object Document (SOD).
3.  Extracting the Document Signer Certificate (DSC) from the SOD.
4.  Finding the issuing CSCA for the DSC in the trusted store.
5.  Verifying the authenticity of the DSC against the CSCA's public key.
6.  Verifying the SOD's signature against the now-trusted DSC's public key.
7.  Comparing the hash of Data Group 1 (DG1) with the expected hash in the SOD.
"""
import base64
import logging
import hashlib
import os
import glob
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from pymrtd.ef.sod import SOD

# Import the configuration which provides CSCA_DIR
import config
from models import VerifyRequest

logger = logging.getLogger(__name__)
# Enable debug logging during tests to capture detailed SOD parsing info.
# This is intentionally verbose for debugging unit tests; remove or lower in production.
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.DEBUG)
router = APIRouter()

# --- Pre-load CSCA certs for performance ---
# This loads all certificates from the directory prepared by config.py on startup.
CSCA_CERTS: List[x509.Certificate] = []
if config.CSCA_DIR and os.path.isdir(config.CSCA_DIR):
    logger.info(f"Loading CSCA certificates from: {config.CSCA_DIR}")
    for cert_path in glob.glob(os.path.join(config.CSCA_DIR, "*.*")):
        try:
            with open(cert_path, "rb") as f:
                # All certs extracted by the config are in DER format
                CSCA_CERTS.append(x509.load_der_x509_certificate(f.read()))
        except Exception as e:
            logger.warning(f"Could not load certificate {os.path.basename(cert_path)}: {e}")
    logger.info(f"Loaded {len(CSCA_CERTS)} CSCA certificates.")
else:
    logger.error("config.CSCA_DIR is not set or not a directory. Passive Authentication will fail.")


def _strip_base64_prefix(b64: str) -> str:
    """Removes 'data:[...];base64,' prefix if present."""
    return b64.split(",", 1)[1] if "," in b64 else b64


def _find_issuer_in_csca(dsc_cert: x509.Certificate, csca_certs: List[x509.Certificate]) -> Optional[x509.Certificate]:
    """Finds the CSCA certificate that issued the DSC by matching subject/issuer names."""
    for csca in csca_certs:
        if csca.subject == dsc_cert.issuer:
            return csca
    return None


def _verify_certificate_signature(
    cert_to_verify: x509.Certificate, issuer_public_key: CertificatePublicKeyTypes
) -> bool:
    """Verifies the signature of a certificate using the issuer's public key."""
    try:
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                ec.ECDSA(cert_to_verify.signature_hash_algorithm),
            )
        else: # Handles RSA and other key types
             issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Certificate signature verification failed with an unexpected error: {e}")
        return False


@router.post("/verify", summary="Verify DG1 and SOD from an ePassport")
async def verify(req: VerifyRequest):
    if not req.dg1:
        raise HTTPException(status_code=400, detail="Missing required field: dg1")
    if not req.sod:
        raise HTTPException(status_code=400, detail="Missing required field: sod")

    if not CSCA_CERTS:
        raise HTTPException(status_code=500, detail="Server is misconfigured: No CSCA certificates loaded for trust validation.")

    # 1. Decode inputs
    try:
        dg1_bytes = base64.b64decode(_strip_base64_prefix(req.dg1))
        sod_bytes = base64.b64decode(_strip_base64_prefix(req.sod))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Base64 input: {e}")

    # 2. Parse SOD and extract Document Signer Certificate (DSC)
    try:
        sod_obj = SOD.load(sod_bytes)
        signed_data = sod_obj.signedData

        # Debug: log signer and certificate information to help diagnose linkage issues
        logger.debug("SOD parsed. SignerInfos and Embedded Certificates:")
        try:
            for idx, si in enumerate(getattr(sod_obj, "signers", []) or []):
                try:
                    sid_native = si['sid'].native if 'sid' in si else None
                except Exception:
                    sid_native = None
                logger.debug(f"  Signer[{idx}]: sid={sid_native}")
        except Exception as e:
            logger.debug(f"  Could not enumerate signers: {e}")

        try:
            for idx, cert_choice in enumerate(getattr(signed_data, "certificates", []) or []):
                try:
                    der = cert_choice.dump() if hasattr(cert_choice, "dump") else cert_choice
                    loaded = x509.load_der_x509_certificate(der)
                    logger.debug(f"  Cert[{idx}]: subject={loaded.subject.rfc4514_string()}, serial={loaded.serial_number}")
                except Exception as e:
                    logger.debug(f"  Cert[{idx}]: (could not load as cryptography cert) {e}")
        except Exception as e:
            logger.debug(f"  Could not enumerate certificates: {e}")

        signer_certs = sod_obj.dscCertificates or []
        if not signer_certs:
             raise ValueError("SOD does not contain a Document Signer Certificate.")

        # Normalize to both an asn1/pymrtd certificate object and a cryptography.x509.Certificate
        try:
            first_choice = signer_certs[0]
            if hasattr(first_choice, "chosen"):
                dsc_cert_asn1 = first_choice.chosen
                der = dsc_cert_asn1.dump()
            elif hasattr(first_choice, "dump"):
                dsc_cert_asn1 = first_choice
                der = dsc_cert_asn1.dump()
            else:
                raise ValueError("Unsupported certificate object in SOD")
            dsc_cert = x509.load_der_x509_certificate(der)
        except Exception as e:
            raise ValueError(f"Failed to extract DSC as cryptography certificate: {e}")

        logger.debug(f"Extracted DSC: subject={dsc_cert.subject.rfc4514_string()}, serial={dsc_cert.serial_number}")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse SOD or extract DSC: {e}")

    # 3. Perform Trust Chain Validation
    now_utc = datetime.now(timezone.utc)
    issuer_csca = _find_issuer_in_csca(dsc_cert, CSCA_CERTS)
    
    if not issuer_csca:
        chain_valid = False
        chain_failure_reason = "Issuing CSCA not found in trust store."
    else:
        # cryptography.x509.Certificate properties are `not_valid_before` and `not_valid_after`.
        # Ensure they are timezone-aware (assume UTC for naive datetimes) before comparing.
        def _to_aware(dt):
            return dt if getattr(dt, "tzinfo", None) is not None else dt.replace(tzinfo=timezone.utc)
    
        csca_is_valid = _to_aware(issuer_csca.not_valid_before) <= now_utc <= _to_aware(issuer_csca.not_valid_after)
        dsc_is_valid = _to_aware(dsc_cert.not_valid_before) <= now_utc <= _to_aware(dsc_cert.not_valid_after)
        dsc_signature_is_valid = _verify_certificate_signature(dsc_cert, issuer_csca.public_key())
        chain_valid = csca_is_valid and dsc_is_valid and dsc_signature_is_valid
        if not csca_is_valid:
            chain_failure_reason = "CSCA certificate has expired or is not yet valid."
        elif not dsc_is_valid:
            chain_failure_reason = "DSC certificate has expired or is not yet valid."
        elif not dsc_signature_is_valid:
            chain_failure_reason = "DSC signature is invalid (could not be verified by CSCA)."
        else:
            chain_failure_reason = None
        
    # 4. Verify SOD signature using the (now trusted) DSC public key
    sod_signature_valid = False
    if chain_valid:
        try:
            # Identify SignerInfo object
            si = sod_obj.signers[0] if getattr(sod_obj, "signers", None) else None
            logger.debug(f"Verifying SOD: SignerInfo present: {si is not None}")
            if si is None:
                raise ValueError("No SignerInfo found in SOD to perform signature verification.")

            # Use pymrtd helper to retrieve the matching DSC certificate object expected by SOD.verify()
            try:
                dsc_pymrt = sod_obj.getDscCertificate(si)
            except Exception as e:
                raise ValueError(f"Could not resolve DSC certificate from SOD for SignerInfo: {e}")

            logger.debug(f"Using DSC (pymrtd) for verification: type={type(dsc_pymrt)}")

            # Call pymrtd's verify with explicit SignerInfo and the pymrtd DSC object
            sod_obj.verify(si, dsc_pymrt)
            sod_signature_valid = True
        except Exception as e:
            logger.warning(f"pymrtd sod_obj.verify() failed: {e}")
            sod_signature_valid = False

    # 5. Verify DG1 Hash
    dg1_sha256_hex = hashlib.sha256(dg1_bytes).hexdigest()
    # Extract expected DG1 hash from the parsed SOD using pymrtd API
    dg1_expected_hash_hex = ""
    try:
        dg1_expected_hash_hex = ""
        lds = sod_obj.ldsSecurityObject
        # Prefer the library-provided property if available
        dg_hashes = getattr(lds, "dgHashes", None)
        if dg_hashes is None:
            dg_hashes = getattr(lds, "dataGroupHashValues", None) or []

        # Iterate and find data group number == 1, using DataGroupHash API
        for dg in dg_hashes:
            try:
                num = None
                # Pymrtd DataGroupHash exposes .number which is a DataGroupNumber with .value
                if hasattr(dg, "number"):
                    num_attr = dg.number
                    # Try common access patterns to retrieve an integer
                    if hasattr(num_attr, "value"):
                        num = num_attr.value
                    elif hasattr(num_attr, "native"):
                        num = num_attr.native
                    else:
                        try:
                            num = int(num_attr)
                        except Exception:
                            num = None
                # If found, extract the hash bytes
                if num == 1:
                    if hasattr(dg, "hash"):
                        dg1_expected_hash_hex = dg.hash.hex()
                    else:
                        # fallback to field access
                        try:
                            dg1_expected_hash_hex = dg["dataGroupHashValue"].native.hex()
                        except Exception:
                            dg1_expected_hash_hex = ""
                    break
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"Failed to extract DG1 hash from SOD: {e}")
        dg1_expected_hash_hex = ""
    dg1_matches = (dg1_expected_hash_hex == dg1_sha256_hex)
    # Some older passports might use SHA-1
    if not dg1_matches and len(dg1_expected_hash_hex) == 40:
        dg1_matches = (dg1_expected_hash_hex == hashlib.sha1(dg1_bytes).hexdigest())

    # 6. Final verdict and detailed response
    passive_auth_passed = chain_valid and sod_signature_valid and dg1_matches
    
    return {
        "passive_authentication_passed": passive_auth_passed,
        "details": {
            "trust_chain": {
                "status": "VALID" if chain_valid else "INVALID",
                "failure_reason": chain_failure_reason,
                "csca_found": issuer_csca is not None,
                "csca_subject": issuer_csca.subject.rfc4514_string() if issuer_csca else None,
                "dsc_signature_verified_by_csca": dsc_signature_is_valid if issuer_csca else False,
                "csca_validity_period_ok": csca_is_valid if issuer_csca else False,
                "dsc_validity_period_ok": dsc_is_valid if issuer_csca else False,
            },
            "sod_signature": {
                "status": "VALID" if sod_signature_valid else "INVALID",
                "dsc_subject": dsc_cert.subject.rfc4514_string(),
                "dsc_serial": dsc_cert.serial_number,
            },
            "dg1_hash_integrity": {
                "status": "VALID" if dg1_matches else "INVALID",
                "dg1_calculated_sha256": dg1_sha256_hex,
                "sod_expected_hash": dg1_expected_hash_hex,
            }
        }
    }