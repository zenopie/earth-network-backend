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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

# 'pymrtd' is a specialized library for parsing and handling the complex data
# structures defined by ICAO for Machine Readable Travel Documents (MRTDs).
from pymrtd.ef.sod import SOD

# --- LOGGING SETUP ---
# A logger is configured to provide output for important verification events.
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


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
        return keyid
    except Exception:
        # This is not an error; many certificates might not have this extension.
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
        return digest
    except Exception:
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

    return candidates


def _verify_certificate_signature(
    cert_to_verify: x509.Certificate, issuer_cert: x509.Certificate
) -> bool:
    """
    WHY: This is the core cryptographic verification function using OpenSSL.
    It verifies that cert_to_verify was signed by issuer_cert.

    Uses OpenSSL CLI because it supports ECDSA keys with explicit parameters
    that the Python cryptography library does not support (like Nigeria CSCA certs).
    """
    import subprocess
    import tempfile

    try:
        # Write both certificates to temporary PEM files (OpenSSL verify needs PEM)
        from cryptography.hazmat.primitives.serialization import Encoding as SerEncoding

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as cert_file:
            cert_file.write(cert_to_verify.public_bytes(SerEncoding.PEM))
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as issuer_file:
            issuer_file.write(issuer_cert.public_bytes(SerEncoding.PEM))
            issuer_path = issuer_file.name

        try:
            # Use OpenSSL to verify: does issuer_cert validate cert_to_verify?
            # -CAfile: trusted CA certificate
            # -no_check_time: we handle validity period checks separately
            result = subprocess.run(
                ['openssl', 'verify', '-CAfile', issuer_path,
                 '-no_check_time', cert_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            # OpenSSL outputs "cert_path: OK" on success
            success = result.returncode == 0 and 'OK' in result.stdout

            if not success:
                logger.debug(f"OpenSSL verify failed: {result.stdout} {result.stderr}")

            return success

        finally:
            # Clean up temp files
            try:
                os.unlink(cert_path)
                os.unlink(issuer_path)
            except:
                pass

    except subprocess.TimeoutExpired:
        logger.warning("OpenSSL verify timed out")
        return False
    except FileNotFoundError:
        logger.error("OpenSSL binary not found - please install OpenSSL")
        return False
    except Exception as e:
        logger.debug(f"OpenSSL verification exception: {e}")
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
        # Find certificate files in the directory (DER/CER/CRT formats).
        cert_extensions = ("*.der", "*.cer", "*.crt", "*.DER", "*.CER", "*.CRT")
        cert_files = []
        for ext in cert_extensions:
            cert_files.extend(glob.glob(os.path.join(csca_dir, ext)))
        for cert_path in cert_files:
            try:
                with open(cert_path, "rb") as f:
                    # Attempt to load each file as a DER-encoded X.509 certificate.
                    certs.append(x509.load_der_x509_certificate(f.read()))
            except Exception as e:
                logger.warning(f"Could not load certificate {os.path.basename(cert_path)}: {e}")
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
            print(f"📄 DSC Issuer (CSCA needed): {dsc_cert.issuer.rfc4514_string()}")
            print(f"📄 DSC Subject: {dsc_cert.subject.rfc4514_string()}")
        except Exception as e:
            raise SODParseError(str(e))

        # --- STEP 3: Trust Chain Validation ---
        # This is the most critical security step. We must verify that the DSC we
        # just extracted was legitimately issued by a trusted CSCA.

        now_utc = datetime.now(timezone.utc) # Get the current time for validity checks.
        issuer_csca: Optional[x509.Certificate] = None
        dsc_signature_is_valid = False
        csca_is_valid = False

        # Find the potential issuing CSCA candidates from our trust store.
        issuer_candidates = _find_issuer_candidates(dsc_cert, self.csca_certs)
        
        # Iterate through the prioritized list of candidates.
        for idx, cand in enumerate(issuer_candidates):
            try:
                # Check 1: Is the candidate CSCA itself currently valid?
                cand_not_before = (
                    cand.not_valid_before
                    if getattr(cand.not_valid_before, "tzinfo", None)
                    else cand.not_valid_before.replace(tzinfo=timezone.utc)
                )
                cand_not_after = (
                    cand.not_valid_after
                    if getattr(cand.not_valid_after, "tzinfo", None)
                    else cand.not_valid_after.replace(tzinfo=timezone.utc)
                )
                cand_valid = cand_not_before <= now_utc <= cand_not_after
                
                # Check 2: Does this candidate CSCA certificate successfully verify the DSC's signature?
                if _verify_certificate_signature(dsc_cert, cand):
                    # If YES, we have found our issuer!
                    issuer_csca = cand
                    dsc_signature_is_valid = True
                    csca_is_valid = cand_valid
                    break # Stop searching.
            except Exception as e:
                logger.debug(f"CSCA candidate verification failed: {e}")
                continue

        def _to_aware(dt):
            return dt if getattr(dt, "tzinfo", None) is not None else dt.replace(tzinfo=timezone.utc)

        dsc_is_valid = _to_aware(dsc_cert.not_valid_before) <= now_utc <= _to_aware(dsc_cert.not_valid_after)

        # Determine the final status of the trust chain.
        if issuer_csca is None:
            chain_valid = False
            chain_failure_reason = "Issuing CSCA not found in trust store or signature mismatch."
            print(f"❌ No matching CSCA found for DSC issuer: {dsc_cert.issuer.rfc4514_string()}")
            print(f"❌ Total CSCA certs in trust store: {len(self.csca_certs)}")
            logger.warning(f"❌ Trust chain validation failed: {chain_failure_reason}")
        else:
            # The chain is valid only if all checks passed.
            chain_valid = csca_is_valid and dsc_is_valid and dsc_signature_is_valid
            if not csca_is_valid:
                chain_failure_reason = "CSCA certificate has expired or is not yet valid."
                logger.warning(f"❌ Trust chain validation failed: {chain_failure_reason} | CSCA: {issuer_csca.subject.rfc4514_string()}")
            elif not dsc_is_valid:
                chain_failure_reason = "DSC certificate has expired or is not yet valid."
                logger.warning(f"❌ Trust chain validation failed: {chain_failure_reason} | CSCA: {issuer_csca.subject.rfc4514_string()}")
            elif not dsc_signature_is_valid:
                chain_failure_reason = "DSC signature is invalid (could not be verified by CSCA)."
                logger.warning(f"❌ Trust chain validation failed: {chain_failure_reason} | CSCA: {issuer_csca.subject.rfc4514_string()}")
            else:
                chain_failure_reason = None
                print(f"✅ Trust chain validated successfully | CSCA: {issuer_csca.subject.rfc4514_string()}")
        
        # --- STEP 4: Verify SOD Signature ---
        # WHY: Now that we trust the DSC, we can use its public key to verify the
        # signature on the SOD itself. This confirms that the list of data group hashes
        # contained within the SOD has not been altered.
        sod_signature_valid = False
        if chain_valid:
            try:
                # Manual SOD signature verification following ICAO 9303 standard
                si = sod_obj.signers[0]
                signed_attrs = si['signed_attrs']

                # The signature is computed over the DER encoding of the signed attributes
                # BUT with the tag changed from context-specific [0] to SET OF (0x31)
                # This is a critical ICAO 9303 requirement that pymrtd sometimes mishandles
                signed_attrs_bytes = signed_attrs.dump()

                # Replace the implicit [0] tag (0xA0) with SET OF tag (0x31)
                if signed_attrs_bytes[0] == 0xA0:
                    signed_attrs_bytes = b'\x31' + signed_attrs_bytes[1:]

                # Extract signature and algorithm info
                signature_bytes = si['signature'].native
                digest_algo = si['digest_algorithm']['algorithm'].native
                sig_algo = si['signature_algorithm']['algorithm'].native

                # Map algorithm OIDs to hash algorithms
                hash_algo_map = {
                    'sha1': hashes.SHA1(),
                    'sha256': hashes.SHA256(),
                    'sha384': hashes.SHA384(),
                    'sha512': hashes.SHA512(),
                }
                hash_algo = hash_algo_map.get(digest_algo)
                if not hash_algo:
                    raise ValueError(f"Unsupported digest algorithm: {digest_algo}")

                # Get the DSC public key for verification
                # Try to get public key - may fail for ECDSA explicit parameters
                dsc_public_key = None
                try:
                    dsc_public_key = dsc_cert.public_key()
                except ValueError as e:
                    if "explicit parameters" in str(e):
                        # DSC uses ECDSA explicit parameters - use OpenSSL fallback
                        logger.info("DSC uses ECDSA explicit parameters - using OpenSSL for SOD verification")
                        import subprocess
                        import tempfile

                        # Write public key and signed data to temp files
                        with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as cert_file:
                            cert_file.write(dsc_cert.public_bytes(Encoding.DER))
                            cert_path = cert_file.name

                        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as data_file:
                            data_file.write(signed_attrs_bytes)
                            data_path = data_file.name

                        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as sig_file:
                            sig_file.write(signature_bytes)
                            sig_path = sig_file.name

                        try:
                            # Extract public key from certificate
                            pubkey_result = subprocess.run(
                                ['openssl', 'x509', '-inform', 'DER', '-in', cert_path, '-pubkey', '-noout'],
                                capture_output=True,
                                timeout=5
                            )

                            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as pub_file:
                                pub_file.write(pubkey_result.stdout)
                                pub_path = pub_file.name

                            # Determine algorithm for OpenSSL
                            openssl_hash = digest_algo if digest_algo != 'sha1' else 'sha1'

                            # Verify signature
                            verify_result = subprocess.run(
                                ['openssl', 'dgst', f'-{openssl_hash}', '-verify', pub_path,
                                 '-signature', sig_path, data_path],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )

                            if verify_result.returncode == 0 and 'Verified OK' in verify_result.stdout:
                                sod_signature_valid = True
                                print("✅ SOD signature verified successfully (OpenSSL)")
                            else:
                                raise ValueError(f"OpenSSL verification failed: {verify_result.stderr}")

                        finally:
                            for path in [cert_path, data_path, sig_path, pub_path]:
                                try:
                                    os.unlink(path)
                                except:
                                    pass
                    else:
                        raise

                # Verify based on key type (standard cryptography library path)
                if dsc_public_key is not None:
                    if isinstance(dsc_public_key, rsa.RSAPublicKey):
                        is_pss = 'pss' in sig_algo.lower() or sig_algo == 'rsassa_pss'

                        if is_pss:
                            dsc_public_key.verify(
                                signature_bytes,
                                signed_attrs_bytes,
                                padding.PSS(
                                    mgf=padding.MGF1(hash_algo),
                                    salt_length=padding.PSS.AUTO
                                ),
                                hash_algo
                            )
                        else:
                            dsc_public_key.verify(
                                signature_bytes,
                                signed_attrs_bytes,
                                padding.PKCS1v15(),
                                hash_algo
                            )
                    elif isinstance(dsc_public_key, ec.EllipticCurvePublicKey):
                        dsc_public_key.verify(
                            signature_bytes,
                            signed_attrs_bytes,
                            ec.ECDSA(hash_algo)
                        )
                    else:
                        raise ValueError(f"Unsupported public key type: {type(dsc_public_key)}")

                    sod_signature_valid = True
                    print("✅ SOD signature verified successfully")
            except InvalidSignature:
                logger.warning("❌ SOD signature verification failed: Invalid signature")
                sod_signature_valid = False
            except Exception as e:
                logger.error(f"❌ SOD signature verification failed: {e}")
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

            # Try different ways to access data group hashes
            dg_hashes = None
            if hasattr(lds, "dataGroupHashValues"):
                dg_hashes = lds.dataGroupHashValues
            elif hasattr(lds, "dgHashes"):
                dg_hashes = lds.dgHashes
            elif hasattr(lds, "hashValues"):
                dg_hashes = lds.hashValues

            if dg_hashes:
                for dg in dg_hashes:
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

                    if dg_number == 1 and dg_hash:
                        sod_expected_hash = dg_hash.hex() if hasattr(dg_hash, 'hex') else dg_hash
                        break

            if not sod_expected_hash:
                logger.warning("❌ No DG1 hash found in SOD")
        except Exception as e:
            logger.error(f"❌ Failed to extract DG1 hash from SOD: {e}")
        
        # Compare the calculated hash with the expected hash.
        dg1_matches = (sod_expected_hash == dg1_calculated_hash)

        # --- STEP 6: Check Passport Expiration Date ---
        # Parse the DG1 MRZ data to extract and validate passport expiration
        passport_expired = False
        passport_expiry_date = None
        passport_expiry_reason = None

        try:
            # DG1 contains the MRZ (Machine Readable Zone) data
            # The MRZ format varies but expiration date is typically at fixed positions
            dg1_text = dg1_bytes.decode('utf-8', errors='ignore')
            # Note: Not logging DG1 content as it contains personal information

            # Try to find expiration date in YYMMDD format (common in MRZ)
            # Look for patterns like dates in the MRZ
            import re

            # MRZ typically has expiration in YYMMDD format
            # Look for 6-digit sequences that could be dates
            date_pattern = r'(\d{6})'
            date_matches = re.findall(date_pattern, dg1_text)

            for date_str in date_matches:
                try:
                    # Try to parse as YYMMDD (assuming 20xx for now)
                    year = 2000 + int(date_str[:2])
                    month = int(date_str[2:4])
                    day = int(date_str[4:6])

                    # Validate date ranges
                    if 1 <= month <= 12 and 1 <= day <= 31 and 2020 <= year <= 2050:
                        candidate_date = datetime(year, month, day, tzinfo=timezone.utc)

                        # Check if this date is in the future (likely expiration)
                        if candidate_date > now_utc:
                            passport_expiry_date = candidate_date
                            break

                except ValueError:
                    continue  # Invalid date, try next match

            if passport_expiry_date:
                passport_expired = passport_expiry_date <= now_utc
                if passport_expired:
                    passport_expiry_reason = f"Passport expired on {passport_expiry_date.strftime('%Y-%m-%d')}"
                else:
                    passport_expiry_reason = None
            else:
                logger.warning("❌ Could not extract passport expiration date from DG1 MRZ data")
                passport_expiry_reason = "Unable to determine passport expiration date"

        except Exception as e:
            logger.warning(f"❌ Error parsing DG1 for expiration date: {e}")
            passport_expiry_reason = f"Error parsing passport expiration: {str(e)}"
        # Fallback for older passports that might use SHA-1.
        if not dg1_matches and len(sod_expected_hash) == 40:
             dg1_matches = (sod_expected_hash == hashlib.sha1(dg1_bytes).hexdigest())

        # --- STEP 7: Final Verdict and Response ---
        # WHY: The overall process passes only if every single step succeeded.
        # This function returns a detailed dictionary that clearly states the
        # final result and provides granular details about each step, which is
        # invaluable for auditing and debugging.
        passive_auth_passed = chain_valid and sod_signature_valid and dg1_matches and not passport_expired

        # Determine overall failure reason for app display
        failure_reason = None
        if not passive_auth_passed:
            if not chain_valid:
                failure_reason = f"Trust chain validation failed: {chain_failure_reason}"
            elif not sod_signature_valid:
                failure_reason = "SOD signature verification failed - document integrity could not be verified"
                logger.warning("❌ Passport verification failed: SOD signature invalid")
            elif not dg1_matches:
                failure_reason = "DG1 hash mismatch - document data has been tampered with"
                logger.warning("❌ Passport verification failed: DG1 hash mismatch")
            elif passport_expired:
                failure_reason = passport_expiry_reason
                logger.warning(f"❌ Passport verification failed: {passport_expiry_reason}")
        else:
            print(f"✅ Passport verification successful | CSCA: {issuer_csca.subject.rfc4514_string() if issuer_csca else 'N/A'}")

        return {
            "passive_authentication_passed": passive_auth_passed,
            "failure_reason": failure_reason,
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
                "passport_expiration": {
                    "status": "VALID" if not passport_expired else "EXPIRED",
                    "expiry_date": passport_expiry_date.isoformat() if passport_expiry_date else None,
                    "expired": passport_expired,
                    "failure_reason": passport_expiry_reason if passport_expired else None,
                },
            },
        }