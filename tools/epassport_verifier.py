# /tools/epassport_verifier.py
"""
Passive Authentication (ePassport) verification utility.

This module encapsulates the verification logic previously embedded in the
/routers/verify.py endpoint into a reusable tool. It performs:

1) Loading CSCA trust anchors (DER X.509 certificates)
2) Parsing the EF.SOD and extracting the Document Signer Certificate (DSC)
3) Finding and validating the issuing CSCA for the DSC (AKI/SKI/Subject heuristics)
4) Verifying the DSC signature with the CSCA public key
5) Verifying the SOD signature with the DSC certificate
6) Verifying DG1 hash integrity

Usage:
    from tools.epassport_verifier import EPassportVerifier
    verifier = EPassportVerifier(EPassportVerifier.load_csca_from_dir("/path/to/csca/dir"))
    result = verifier.verify(dg1_b64, sod_b64)
"""

# --- PREAMBLE AND IMPORTS ---
# These libraries provide the necessary tools for cryptographic operations,
# data manipulation, and ePassport data structure parsing.

from __future__ import annotations # Allows type hinting a class within its own definition.

import base64  # For decoding the Base64-encoded passport data.
import glob    # For finding all certificate files in a directory.
import hashlib # For calculating cryptographic hashes (SHA-1, SHA-256) of data groups.
import logging # For providing detailed diagnostic output during verification.
import os      # For interacting with the file system (e.g., checking directories).
from datetime import datetime, timezone # For handling certificate validity periods correctly.
from typing import List, Optional      # For type hinting to improve code clarity.

# The 'cryptography' library is the core engine for all cryptographic tasks.
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

# 'pymrtd' is a specialized library for parsing and handling the complex data
# structures defined by ICAO for Machine Readable Travel Documents (MRTDs).
from pymrtd.ef.sod import SOD

# --- LOGGING SETUP ---
# A logger is configured to provide verbose output. This is extremely useful
# for debugging complex cryptographic issues, such as why a signature
# verification failed or why a specific certificate was chosen.
logger = logging.getLogger(__name__)
# Intentionally verbose for development; callers can override the level.
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.DEBUG)


# ----- Custom Exceptions -----
# Defining custom exceptions makes error handling more specific and clear.
# Instead of a generic Exception, we know exactly what kind of error occurred.

class InvalidBase64Error(Exception):
    """Raised when input data cannot be decoded from Base64."""
    pass


class SODParseError(Exception):
    """Raised when the Security Object Document (SOD) cannot be parsed."""
    pass


# ----- Utility Functions -----
# These small helper functions perform common, reusable tasks.

def _strip_base64_prefix(b64: str) -> str:
    """
    WHY: Input data might come from a web source with a data URI prefix
    (e.g., 'data:application/octet-stream;base64,'). This function cleans the
    input to get only the pure Base64 string needed for decoding.
    """
    return b64.split(",", 1)[1] if "," in b64 else b64


def _bhex(b: Optional[bytes]) -> Optional[str]:
    """
    WHY: Raw bytes are unreadable in logs. This converts bytes into a
    hexadecimal string, which is a standard and readable way to represent
    binary data like keys and digests.
    """
    try:
        return b.hex() if isinstance(b, (bytes, bytearray)) else None
    except Exception:
        return None


def _get_aki_keyid(cert: x509.Certificate) -> Optional[bytes]:
    """
    WHY: The Authority Key Identifier (AKI) is an extension in a certificate
    that helps identify the specific key of the issuer (the "Authority"). It's
    a crucial piece of data for reliably building the certificate chain,
    linking a child certificate (like a DSC) to its parent (the CSCA).
    """
    try:
        # Tries to find the AKI extension within the certificate.
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        # Extracts the 'key_identifier' part from the extension.
        keyid = getattr(aki, "key_identifier", None)
        logger.debug(
            f"AKI lookup: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, keyid={_bhex(keyid)}"
        )
        return keyid
    except Exception as e:
        # This is not an error; many certificates might not have this extension.
        logger.debug(
            f"AKI missing: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, err={e}"
        )
        return None


def _get_ski_keyid(cert: x509.Certificate) -> Optional[bytes]:
    """
    WHY: The Subject Key Identifier (SKI) is an identifier for the public key
    *of this certificate*. It's the counterpart to the AKI. A parent's SKI should
    match its child's AKI. This function extracts the SKI for that comparison.
    """
    try:
        # Tries to find the SKI extension within the certificate.
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        # Extracts the digest (the identifier itself).
        digest = getattr(ski, "digest", None)
        logger.debug(
            f"SKI lookup: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, digest={_bhex(digest)}"
        )
        return digest
    except Exception as e:
        logger.debug(
            f"SKI missing: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, err={e}"
        )
        return None


def _find_issuer_candidates(dsc_cert: x509.Certificate, csca_certs: List[x509.Certificate]) -> List[x509.Certificate]:
    """
    WHY: This is a critical heuristic function. Given a Document Signer Certificate (DSC),
    we need to find which Country Signing CA (CSCA) from our trust store issued it.
    This function intelligently searches and prioritizes the list of possible CSCAs
    to find the correct issuer quickly and reliably.
    """
    # Get the issuer's name and the AKI from the DSC.
    issuer_name = dsc_cert.issuer
    aki_keyid = _get_aki_keyid(dsc_cert)

    # Pre-filter for performance: get all CSCAs that match by name and pre-calculate their SKIs.
    subj_matches = [c for c in csca_certs if c.subject == issuer_name]
    ski_map = {c: _get_ski_keyid(c) for c in csca_certs}

    logger.debug(
        f"Issuer matching: dsc_issuer={issuer_name.rfc4514_string()}, dsc_aki={_bhex(aki_keyid)}, subj_matches={len(subj_matches)}"
    )

    candidates: List[x509.Certificate] = []

    # Priority 1: The Gold Standard. The CSCA's subject name matches the DSC's issuer name,
    # AND the CSCA's SKI matches the DSC's AKI. This is the most certain link.
    if aki_keyid:
        for c in subj_matches:
            if ski_map.get(c) == aki_keyid:
                candidates.append(c)

    # Priority 2: Subject Match. If the AKI/SKI link isn't available, matching the
    # issuer/subject names is the next best thing.
    for c in subj_matches:
        if c not in candidates:
            candidates.append(c)

    # Priority 3: Key Identifier Match. This handles cases where a country may issue a new
    # CSCA with a new name but the same key (a "rollover"). The key identifiers will still match.
    if aki_keyid:
        for c in csca_certs:
            if ski_map.get(c) == aki_keyid and c not in candidates:
                candidates.append(c)

    # Priority 4: Last Resort. If no other heuristics work, add all remaining CSCAs.
    # The signature check will be attempted against each of them.
    for c in csca_certs:
        if c not in candidates:
            candidates.append(c)
    
    # Detailed logging to help debug the selection process.
    try:
        lines = []
        for c in candidates:
            ski = ski_map.get(c)
            subj_match = (c.subject == issuer_name)
            ski_match = (aki_keyid is not None and ski == aki_keyid)
            lines.append(
                f"  - subject={c.subject.rfc4514_string()} | SKI={_bhex(ski)} | subj_match={subj_match} | ski==aki={ski_match}"
            )
        logger.debug("Issuer candidates (priority order):\n" + ("\n".join(lines) if lines else "  <none>"))
    except Exception as e:
        logger.debug(f"Failed to emit issuer candidates detail: {e}", exc_info=True)

    return candidates


def _verify_certificate_signature(
    cert_to_verify: x509.Certificate, issuer_public_key: CertificatePublicKeyTypes
) -> bool:
    """
    WHY: This is the core cryptographic verification function. It takes a certificate
    and the public key of its supposed issuer and confirms that the signature on the
    certificate is valid. This function must support the different algorithms used
    in ePassports (RSA with different paddings and ECDSA).
    """
    try:
        # Extract the necessary components from the certificate:
        # - signature_hash_algorithm: e.g., SHA256, SHA1
        # - signature: The raw bytes of the digital signature.
        # - tbs_certificate_bytes: "To-Be-Signed" bytes, the actual data that was signed.
        sig_hash_algo = cert_to_verify.signature_hash_algorithm
        algo_oid = getattr(cert_to_verify, "signature_algorithm_oid", None)
        # ... logging details ...

        # --- ECDSA Path ---
        # If the issuer's key is an Elliptic Curve key...
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            # ...use the ECDSA verification method.
            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                ec.ECDSA(sig_hash_algo),
            )
            logger.debug("Certificate signature verified using ECDSA.")
            return True

        # --- RSA Path ---
        # If the issuer's key is an RSA key...
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # The OID helps determine if RSA-PSS padding was used, which is more secure.
            is_pss = (getattr(getattr(algo_oid, "dotted_string", None), "dotted_string", str(algo_oid)) == "1.2.840.113549.1.1.10")

            if not is_pss:
                # Use the older but still common PKCS1v15 padding for verification.
                logger.debug("Attempting PKCS1v15 verification path.")
                issuer_public_key.verify(
                    cert_to_verify.signature,
                    cert_to_verify.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sig_hash_algo,
                )
                logger.debug("Certificate signature verified using PKCS1v15.")
                return True
            else:
                # Use the modern PSS padding for verification.
                logger.debug("Attempting RSA-PSS verification path.")
                issuer_public_key.verify(
                    cert_to_verify.signature,
                    cert_to_verify.tbs_certificate_bytes,
                    padding.PSS(mgf=padding.MGF1(sig_hash_algo), salt_length=padding.PSS.MAX_LENGTH),
                    sig_hash_algo,
                )
                logger.debug("Certificate signature verified using RSA-PSS.")
                return True

        logger.error(f"Unsupported issuer key type for verification: {type(issuer_public_key)}")
        return False

    except InvalidSignature:
        # This is the expected exception for a failed signature check. It's not an error,
        # it's a verification failure.
        logger.debug("InvalidSignature: certificate signature verification failed.")
        return False
    except Exception as e:
        # Any other exception indicates a problem with the code or data, not just a bad signature.
        logger.error(f"Certificate signature verification failed with an unexpected error: {e}")
        return False


# ----- The Main Verifier Class -----
class EPassportVerifier:
    """Encapsulates the entire Passive Authentication verification logic."""

    def __init__(self, csca_certs: Optional[List[x509.Certificate]] = None) -> None:
        """
        WHY: The verifier must be initialized with the set of trusted root
        certificates (CSCAs). These are the anchors of trust. Without them,
        no verification is possible.
        """
        self.csca_certs: List[x509.Certificate] = csca_certs or []

    @staticmethod
    def load_csca_from_dir(csca_dir: Optional[str]) -> List[x509.Certificate]:
        """
        WHY: This provides a convenient way to populate the trust store. It loads
        all CSCA certificates (which must be in DER binary format) from a given
        directory, making setup easy.
        """
        certs: List[x509.Certificate] = []
        if not csca_dir or not os.path.isdir(csca_dir):
            logger.error("CSCA_DIR is not set or not a directory. Passive Authentication will fail.")
            return certs
        logger.info(f"Loading CSCA certificates from: {csca_dir}")
        # Find all files in the directory.
        for cert_path in glob.glob(os.path.join(csca_dir, "*.*")):
            try:
                with open(cert_path, "rb") as f:
                    # Attempt to load each file as a DER-encoded X.509 certificate.
                    certs.append(x509.load_der_x509_certificate(f.read()))
            except Exception as e:
                logger.warning(f"Could not load certificate {os.path.basename(cert_path)}: {e}")
        logger.info(f"Loaded {len(certs)} CSCA certificates.")
        return certs

    def verify(self, dg1_b64: str, sod_b64: str) -> dict:
        """
        WHY: This is the main public method that executes the full Passive
        Authentication workflow from start to finish.
        """
        if not self.csca_certs:
            raise RuntimeError("No CSCA certificates loaded for trust validation.")

        # --- STEP 1: Decode Inputs ---
        # The input data (DG1 and SOD) from the ePassport chip is typically
        # transmitted in Base64 format. It must be decoded into raw bytes.
        try:
            dg1_bytes = base64.b64decode(_strip_base64_prefix(dg1_b64))
            sod_bytes = base64.b64decode(_strip_base64_prefix(sod_b64))
        except Exception as e:
            raise InvalidBase64Error(str(e))

        # --- STEP 2: Parse SOD and Extract DSC ---
        # The SOD is a complex ASN.1 structure. The pymrtd library is used to
        # parse these bytes into an accessible object. The most important piece
        # of information inside is the Document Signer Certificate (DSC) that
        # was used to sign the passport's data.
        try:
            sod_obj = SOD.load(sod_bytes)
            # The SOD can contain multiple certificates; we typically need the first one.
            signer_certs = sod_obj.dscCertificates or []
            if not signer_certs:
                raise ValueError("SOD does not contain a Document Signer Certificate.")
            
            # Extract the raw DER bytes of the certificate from the parsed SOD object.
            # This logic handles the different ways the certificate might be stored.
            first_choice = signer_certs[0]
            if hasattr(first_choice, "chosen"):
                der = first_choice.chosen.dump()
            elif hasattr(first_choice, "dump"):
                der = first_choice.dump()
            else:
                raise ValueError("Unsupported certificate object in SOD")

            # Load the raw DER bytes into a `cryptography` certificate object for analysis.
            dsc_cert = x509.load_der_x509_certificate(der)
            
            logger.debug(
                f"Extracted DSC: subject={dsc_cert.subject.rfc4514_string()}, serial={dsc_cert.serial_number}"
            )
        except Exception as e:
            raise SODParseError(str(e))

        # --- STEP 3: Trust Chain Validation ---
        # This is the most critical security step. We must verify that the DSC we
        # just extracted was legitimately issued by a trusted CSCA.

        now_utc = datetime.now(timezone.utc) # Get the current time for validity checks.
        issuer_csca: Optional[x509.Certificate] = None
        # ... initialize result flags ...

        # Find the potential issuing CSCA candidates from our trust store.
        issuer_candidates = _find_issuer_candidates(dsc_cert, self.csca_certs)
        
        # Iterate through the prioritized list of candidates.
        for idx, cand in enumerate(issuer_candidates):
            try:
                # Check 1: Is the candidate CSCA itself currently valid?
                cand_not_before = cand.not_valid_before.replace(tzinfo=timezone.utc)
                cand_not_after = cand.not_valid_after.replace(tzinfo=timezone.utc)
                cand_valid = cand_not_before <= now_utc <= cand_not_after
                
                # Check 2: Does this candidate's public key successfully verify the DSC's signature?
                if _verify_certificate_signature(dsc_cert, cand.public_key()):
                    # If YES, we have found our issuer!
                    issuer_csca = cand
                    dsc_signature_is_valid = True
                    csca_is_valid = cand_valid
                    logger.debug(f"Selected CSCA candidate[{idx}] based on successful DSC signature verification.")
                    break # Stop searching.
                else:
                    # If NO, log it and continue to the next candidate.
                    logger.debug(f"CSCA candidate[{idx}] did not verify DSC signature.")
            except Exception as e:
                logger.debug(f"Error while attempting CSCA candidate[{idx}] verification: {e}", exc_info=True)
                continue

        # Check 3: Is the DSC itself currently valid?
        dsc_not_before = dsc_cert.not_valid_before.replace(tzinfo=timezone.utc)
        dsc_not_after = dsc_cert.not_valid_after.replace(tzinfo=timezone.utc)
        dsc_is_valid = dsc_not_before <= now_utc <= dsc_not_after

        # Determine the final status of the trust chain.
        if issuer_csca is None:
            chain_valid = False
            chain_failure_reason = "Issuing CSCA not found in trust store or signature mismatch."
        else:
            # The chain is valid only if all checks passed.
            chain_valid = csca_is_valid and dsc_is_valid and dsc_signature_is_valid
            if not csca_is_valid:
                chain_failure_reason = "CSCA certificate has expired or is not yet valid."
            elif not dsc_is_valid:
                chain_failure_reason = "DSC certificate has expired or is not yet valid."
            elif not dsc_signature_is_valid:
                chain_failure_reason = "DSC signature is invalid (could not be verified by CSCA)."
            else:
                chain_failure_reason = None
        
        # --- STEP 4: Verify SOD Signature ---
        # WHY: Now that we trust the DSC, we can use its public key to verify the
        # signature on the SOD itself. This confirms that the list of data group hashes
        # contained within the SOD has not been altered.
        sod_signature_valid = False
        if chain_valid:
            try:
                # Use the pymrtd library's built-in SOD verification logic.
                si = sod_obj.signers[0]
                dsc_pymrt = sod_obj.getDscCertificate(si)
                sod_obj.verify(si, dsc_pymrt)
                sod_signature_valid = True
                logger.debug("SOD signature verified successfully by pymrtd.")
            except Exception as e:
                # This can fail if the signature is invalid or if there's an issue
                # with the data structures that pymrtd can't handle.
                logger.warning(f"pymrtd sod_obj.verify() failed: {e}", exc_info=True)
                sod_signature_valid = False

        # --- STEP 5: Verify DG1 Hash Integrity ---
        # WHY: This is the final integrity check. We compute a fresh hash of the DG1
        # data we received and compare it to the expected hash that was stored in the
        # cryptographically secured SOD. A match proves the DG1 data is unaltered.
        dg1_calculated_hash = hashlib.sha256(dg1_bytes).hexdigest()
        sod_expected_hash = ""
        try:
            # Extract the expected DG1 hash from the parsed SOD object.
            lds = sod_obj.ldsSecurityObject
            logger.debug(f"LDS Security Object type: {type(lds)}")
            logger.debug(f"LDS Security Object dir: {[attr for attr in dir(lds) if not attr.startswith('_')]}")
            
            # Try different ways to access data group hashes
            dg_hashes = None
            if hasattr(lds, "dataGroupHashValues"):
                dg_hashes = lds.dataGroupHashValues
                logger.debug(f"Found dataGroupHashValues: {type(dg_hashes)} with {len(dg_hashes) if dg_hashes else 0} items")
            elif hasattr(lds, "dgHashes"):
                dg_hashes = lds.dgHashes
                logger.debug(f"Found dgHashes: {type(dg_hashes)} with {len(dg_hashes) if dg_hashes else 0} items")
            elif hasattr(lds, "hashValues"):
                dg_hashes = lds.hashValues
                logger.debug(f"Found hashValues: {type(dg_hashes)} with {len(dg_hashes) if dg_hashes else 0} items")
            
            if dg_hashes:
                for i, dg in enumerate(dg_hashes):
                    logger.debug(f"DG[{i}] type: {type(dg)}, dir: {[attr for attr in dir(dg) if not attr.startswith('_')]}")
                    dg_number = None
                    dg_hash = None
                    
                    # Try different ways to get the data group number
                    if hasattr(dg, "number"):
                        if hasattr(dg.number, "value"):
                            dg_number = dg.number.value
                        else:
                            dg_number = dg.number
                    elif hasattr(dg, "dataGroupNumber"):
                        dg_number = dg.dataGroupNumber
                    
                    # Try different ways to get the hash
                    if hasattr(dg, "hash"):
                        dg_hash = dg.hash
                    elif hasattr(dg, "dataGroupHashValue"):
                        dg_hash = dg.dataGroupHashValue
                    elif hasattr(dg, "hashValue"):
                        dg_hash = dg.hashValue
                    
                    logger.debug(f"DG[{i}]: number={dg_number}, hash_len={len(dg_hash) if dg_hash else 'no hash'}")
                    
                    if dg_number == 1 and dg_hash:
                        sod_expected_hash = dg_hash.hex() if hasattr(dg_hash, 'hex') else dg_hash
                        logger.debug(f"Found DG1 hash: {sod_expected_hash}")
                        break
            
            if not sod_expected_hash:
                logger.warning("No DG1 hash found in SOD")
        except Exception as e:
            logger.error(f"Failed to extract DG1 hash from SOD: {e}", exc_info=True)
        
        # Compare the calculated hash with the expected hash.
        dg1_matches = (sod_expected_hash == dg1_calculated_hash)
        # Fallback for older passports that might use SHA-1.
        if not dg1_matches and len(sod_expected_hash) == 40:
             dg1_matches = (sod_expected_hash == hashlib.sha1(dg1_bytes).hexdigest())

        # --- STEP 6: Final Verdict and Response ---
        # WHY: The overall process passes only if every single step succeeded.
        # This function returns a detailed dictionary that clearly states the
        # final result and provides granular details about each step, which is
        # invaluable for auditing and debugging.
        passive_auth_passed = chain_valid and sod_signature_valid and dg1_matches

        return {
            "passive_authentication_passed": passive_auth_passed,
            "details": {
                "trust_chain": {
                    "status": "VALID" if chain_valid else "INVALID",
                    "failure_reason": chain_failure_reason,
                    "csca_found": issuer_csca is not None,
                    "csca_subject": issuer_csca.subject.rfc4514_string() if issuer_csca else None,
                    "dsc_signature_verified_by_csca": dsc_signature_is_valid,
                    "csca_validity_period_ok": csca_is_valid,
                    "dsc_validity_period_ok": dsc_is_valid,
                },
                "sod_signature": {
                    "status": "VALID" if sod_signature_valid else "INVALID",
                    "dsc_subject": dsc_cert.subject.rfc4514_string(),
                    "dsc_serial": dsc_cert.serial_number,
                },
                "dg1_hash_integrity": {
                    "status": "VALID" if dg1_matches else "INVALID",
                    "dg1_calculated_sha256": dg1_calculated_hash,
                    "sod_expected_hash": sod_expected_hash,
                },
            },
        }