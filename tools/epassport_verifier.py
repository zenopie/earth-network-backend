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

from __future__ import annotations

import base64
import glob
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID
from pymrtd.ef.sod import SOD

logger = logging.getLogger(__name__)
# Intentionally verbose for development; callers can override the level.
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.DEBUG)


# ----- Exceptions -----
class InvalidBase64Error(Exception):
    pass


class SODParseError(Exception):
    pass


# ----- Utilities -----
def _strip_base64_prefix(b64: str) -> str:
    """Remove data:[...];base64, prefix if present."""
    return b64.split(",", 1)[1] if "," in b64 else b64


def _bhex(b: Optional[bytes]) -> Optional[str]:
    """Render bytes as lowercase hex for logs, or None."""
    try:
        return b.hex() if isinstance(b, (bytes, bytearray)) else None
    except Exception:
        return None


def _get_aki_keyid(cert: x509.Certificate) -> Optional[bytes]:
    try:
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        keyid = getattr(aki, "key_identifier", None)
        logger.debug(
            f"AKI lookup: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, keyid={_bhex(keyid)}"
        )
        return keyid
    except Exception as e:
        logger.debug(
            f"AKI missing: subject={cert.subject.rfc4514_string()}, serial={cert.serial_number}, err={e}"
        )
        return None


def _get_ski_keyid(cert: x509.Certificate) -> Optional[bytes]:
    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
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
    Returns a prioritized list of CSCA candidates that could have issued the DSC.
    Priority:
      1) Subject == DSC.issuer AND SKI matches DSC.AKI keyIdentifier
      2) Subject == DSC.issuer
      3) SKI matches DSC.AKI (subject name rollover handling)
      4) All remaining (last resort)
    """
    issuer_name = dsc_cert.issuer
    aki_keyid = _get_aki_keyid(dsc_cert)

    subj_matches = [c for c in csca_certs if c.subject == issuer_name]
    ski_map = {c: _get_ski_keyid(c) for c in csca_certs}

    logger.debug(
        f"Issuer matching: dsc_issuer={issuer_name.rfc4514_string()}, dsc_aki={_bhex(aki_keyid)}, subj_matches={len(subj_matches)}"
    )

    candidates: List[x509.Certificate] = []

    # 1) Subject + SKI==AKI
    if aki_keyid:
        for c in subj_matches:
            if ski_map.get(c) == aki_keyid:
                candidates.append(c)

    # 2) Subject match (order stable)
    for c in subj_matches:
        if c not in candidates:
            candidates.append(c)

    # 3) SKI==AKI regardless of subject
    if aki_keyid:
        for c in csca_certs:
            if ski_map.get(c) == aki_keyid and c not in candidates:
                candidates.append(c)

    # 4) Any remaining
    for c in csca_certs:
        if c not in candidates:
            candidates.append(c)

    # Emit detailed candidate list with reasons
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
    Verifies the signature of a certificate using the issuer's public key.

    Supports:
      - ECDSA (using the certificate's signature hash algorithm)
      - RSA PKCS#1 v1.5 (based on signatureAlgorithm OID)
      - RSA-PSS (when OID indicates RSASSA-PSS)
    """
    try:
        sig_hash_algo = cert_to_verify.signature_hash_algorithm
        algo_oid = getattr(cert_to_verify, "signature_algorithm_oid", None)
        algo_oid_str = None
        try:
            algo_oid_str = getattr(algo_oid, "dotted_string", str(algo_oid))
        except Exception:
            algo_oid_str = str(algo_oid) if algo_oid is not None else None

        logger.debug(
            "Verifying certificate signature: "
            f"sig_algo={sig_hash_algo}, algo_oid={algo_oid_str}, sig_len={len(cert_to_verify.signature)}, "
            f"tbs_len={len(cert_to_verify.tbs_certificate_bytes)}, issuer_key_type={type(issuer_public_key)}"
        )

        # ECDSA path
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            try:
                curve_name = getattr(issuer_public_key.curve, "name", None)
            except Exception:
                curve_name = None
            logger.debug(f"Using ECDSA path: curve={curve_name}")
            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                ec.ECDSA(sig_hash_algo),
            )
            logger.debug("Certificate signature verified using ECDSA.")
            return True

        # RSA path
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            key_bits = getattr(issuer_public_key, "key_size", None)
            logger.debug(f"RSA issuer key detected: key_size={key_bits}, algo_oid={algo_oid_str}")
            # Determine if RSASSA-PSS by OID
            is_pss = False
            try:
                is_pss = (algo_oid_str == "1.2.840.113549.1.1.10")
            except Exception:
                is_pss = False

            if not is_pss:
                logger.debug("Attempting PKCS1v15 verification path.")
                issuer_public_key.verify(
                    cert_to_verify.signature,
                    cert_to_verify.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sig_hash_algo,
                )
                logger.debug("Certificate signature verified using PKCS1v15.")
                return True

            # RSASSA-PSS (best-effort parameterization)
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
        logger.debug("InvalidSignature: certificate signature verification failed.")
        return False
    except Exception as e:
        logger.error(f"Certificate signature verification failed with an unexpected error: {e}")
        return False


# ----- Verifier -----
class EPassportVerifier:
    """Encapsulates Passive Authentication verification."""

    def __init__(self, csca_certs: Optional[List[x509.Certificate]] = None) -> None:
        self.csca_certs: List[x509.Certificate] = csca_certs or []

    @staticmethod
    def load_csca_from_dir(csca_dir: Optional[str]) -> List[x509.Certificate]:
        """Load DER-encoded CSCA certificates from a directory."""
        certs: List[x509.Certificate] = []
        if not csca_dir or not os.path.isdir(csca_dir):
            logger.error("CSCA_DIR is not set or not a directory. Passive Authentication will fail.")
            return certs
        logger.info(f"Loading CSCA certificates from: {csca_dir}")
        for cert_path in glob.glob(os.path.join(csca_dir, "*.*")):
            try:
                with open(cert_path, "rb") as f:
                    certs.append(x509.load_der_x509_certificate(f.read()))
            except Exception as e:
                logger.warning(f"Could not load certificate {os.path.basename(cert_path)}: {e}")
        logger.info(f"Loaded {len(certs)} CSCA certificates.")
        return certs

    def verify(self, dg1_b64: str, sod_b64: str) -> dict:
        """Verify ePassport DG1 and SOD with full trust chain validation."""
        if not self.csca_certs:
            raise RuntimeError("No CSCA certificates loaded for trust validation.")

        # 1) Decode inputs
        try:
            dg1_bytes = base64.b64decode(_strip_base64_prefix(dg1_b64))
            sod_bytes = base64.b64decode(_strip_base64_prefix(sod_b64))
        except Exception as e:
            raise InvalidBase64Error(str(e))

        # 2) Parse SOD and extract DSC
        try:
            sod_obj = SOD.load(sod_bytes)
            signed_data = sod_obj.signedData

            # Diagnostics
            logger.debug("SOD parsed. SignerInfos and Embedded Certificates:")
            try:
                for idx, si in enumerate(getattr(sod_obj, "signers", []) or []):
                    try:
                        sid_native = si["sid"].native if "sid" in si else None
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
                        logger.debug(
                            f"  Cert[{idx}]: subject={loaded.subject.rfc4514_string()}, serial={loaded.serial_number}"
                        )
                    except Exception as e:
                        logger.debug(f"  Cert[{idx}]: (could not load as cryptography cert) {e}")
            except Exception as e:
                logger.debug(f"  Could not enumerate certificates: {e}")

            signer_certs = sod_obj.dscCertificates or []
            if not signer_certs:
                raise ValueError("SOD does not contain a Document Signer Certificate.")

            # Normalize to cryptography.x509.Certificate
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

            logger.debug(
                f"Extracted DSC: subject={dsc_cert.subject.rfc4514_string()}, serial={dsc_cert.serial_number}"
            )
            try:
                dsc_aki = _get_aki_keyid(dsc_cert)
                dsc_ski = _get_ski_keyid(dsc_cert)
                logger.debug(f"Extracted DSC key identifiers: AKI={_bhex(dsc_aki)}, SKI={_bhex(dsc_ski)}")
            except Exception as e:
                logger.debug(f"Could not extract DSC AKI/SKI: {e}", exc_info=True)
        except Exception as e:
            raise SODParseError(str(e))

        # 3) Trust Chain Validation
        now_utc = datetime.now(timezone.utc)

        issuer_csca: Optional[x509.Certificate] = None
        csca_is_valid = False
        dsc_is_valid = False
        dsc_signature_is_valid = False
        chain_valid = False
        chain_failure_reason = None

        issuer_candidates = _find_issuer_candidates(dsc_cert, self.csca_certs)
        logger.debug(f"Found {len(issuer_candidates)} CSCA candidate(s) for issuer matching.")

        for idx, cand in enumerate(issuer_candidates):
            try:
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

                cand_ski = _get_ski_keyid(cand)
                dsc_aki_now = _get_aki_keyid(dsc_cert)
                subj_match = cand.subject == dsc_cert.issuer
                ski_match = (dsc_aki_now is not None and cand_ski == dsc_aki_now)
                logger.debug(
                    "Evaluating CSCA candidate[{idx}]: subject={subj}, SKI={ski}, subj_match={sm}, ski==aki={km}, "
                    "valid_from={nb}, valid_to={na}, now_ok={ok}".format(
                        idx=idx,
                        subj=cand.subject.rfc4514_string(),
                        ski=_bhex(cand_ski),
                        sm=subj_match,
                        km=ski_match,
                        nb=cand_not_before.isoformat(),
                        na=cand_not_after.isoformat(),
                        ok=cand_valid,
                    )
                )

                if _verify_certificate_signature(dsc_cert, cand.public_key()):
                    issuer_csca = cand
                    dsc_signature_is_valid = True
                    csca_is_valid = cand_valid
                    logger.debug(
                        f"Selected CSCA candidate[{idx}] subject={cand.subject.rfc4514_string()} based on successful DSC signature verification."
                    )
                    break
                else:
                    logger.debug(
                        f"CSCA candidate[{idx}] subject={cand.subject.rfc4514_string()} did not verify DSC signature."
                    )
            except Exception as e:
                logger.debug(f"Error while attempting CSCA candidate[{idx}] verification: {e}", exc_info=True)
                continue

        def _to_aware(dt):
            return dt if getattr(dt, "tzinfo", None) is not None else dt.replace(tzinfo=timezone.utc)

        dsc_is_valid = _to_aware(dsc_cert.not_valid_before) <= now_utc <= _to_aware(dsc_cert.not_valid_after)

        if issuer_csca is None:
            chain_valid = False
            chain_failure_reason = "Issuing CSCA not found in trust store or public key mismatch (AKI/SKI/subject)."
        else:
            try:
                try:
                    csca_sig_oid = issuer_csca.signature_algorithm_oid.dotted_string
                except Exception:
                    csca_sig_oid = getattr(issuer_csca, "signature_algorithm_oid", None)
                try:
                    dsc_sig_oid = dsc_cert.signature_algorithm_oid.dotted_string
                except Exception:
                    dsc_sig_oid = getattr(dsc_cert, "signature_algorithm_oid", None)

                issuer_pub = issuer_csca.public_key()
                pub_type = type(issuer_pub).__name__
                pub_details = {}
                if hasattr(issuer_pub, "key_size"):
                    pub_details["key_size"] = getattr(issuer_pub, "key_size")
                if hasattr(issuer_pub, "curve"):
                    pub_details["curve"] = getattr(issuer_pub, "curve").name
                logger.debug(
                    f"Issuer CSCA diagnostics: subject={issuer_csca.subject.rfc4514_string()}, sig_oid={csca_sig_oid}, pub_type={pub_type}, pub_details={pub_details}"
                )
                logger.debug(
                    f"DSC diagnostics: subject={dsc_cert.subject.rfc4514_string()}, serial={dsc_cert.serial_number}, sig_oid={dsc_sig_oid}, sig_len={len(dsc_cert.signature)}"
                )

                # OpenSSL cross-check artifacts disabled; no files written to disk.
                logger.debug("OpenSSL cross-checks disabled; skipping writing DSC/CSCA artifacts to /tmp.")

            except Exception as e:
                logger.debug(f"Failed to emit CSCA/DSC diagnostics: {e}", exc_info=True)

            chain_valid = csca_is_valid and dsc_is_valid and dsc_signature_is_valid

            logger.debug(
                f"Trust chain checks: csca_valid={csca_is_valid}, dsc_valid={dsc_is_valid}, dsc_sig_ok={dsc_signature_is_valid}"
            )

            if not csca_is_valid:
                chain_failure_reason = "CSCA certificate has expired or is not yet valid."
            elif not dsc_is_valid:
                chain_failure_reason = "DSC certificate has expired or is not yet valid."
            elif not dsc_signature_is_valid:
                chain_failure_reason = "DSC signature is invalid (could not be verified by CSCA)."
            else:
                chain_failure_reason = None

        # 4) Verify SOD signature using the DSC public key (via pymrtd)
        sod_signature_valid = False
        if chain_valid:
            try:
                si = sod_obj.signers[0] if getattr(sod_obj, "signers", None) else None
                logger.debug(f"Verifying SOD: SignerInfo present: {si is not None}")
                if si is None:
                    raise ValueError("No SignerInfo found in SOD to perform signature verification.")

                try:
                    logger.debug(f"SignerInfo raw: {repr(si)}")
                except Exception:
                    logger.debug("SignerInfo present but could not be repr()-ed.")

                try:
                    sig_bytes = None
                    sig_algo = None
                    if isinstance(si, dict) and "signature" in si:
                        sig_val = si["signature"]
                        sig_bytes = getattr(sig_val, "native", None) or getattr(sig_val, "dump", lambda: None)()
                    else:
                        sig_attr = getattr(si, "signature", None)
                        if sig_attr is not None:
                            sig_bytes = getattr(sig_attr, "native", None) or getattr(sig_attr, "dump", lambda: None)()
                    try:
                        sig_algo = si.get("signature_algorithm") if isinstance(si, dict) else getattr(
                            si, "signature_algorithm", None
                        )
                    except Exception:
                        sig_algo = None

                    if sig_bytes:
                        logger.debug(f"SignerInfo signature (hex prefix): {sig_bytes.hex()[:128]}...")
                    if sig_algo:
                        try:
                            logger.debug(f"SignerInfo signature algorithm raw: {repr(sig_algo)}")
                        except Exception:
                            logger.debug("SignerInfo signature algorithm present (could not repr()).")
                except Exception as e:
                    logger.debug(f"Could not extract SignerInfo signature diagnostics: {e}", exc_info=True)

                try:
                    dsc_pymrt = sod_obj.getDscCertificate(si)
                except Exception as e:
                    raise ValueError(f"Could not resolve DSC certificate from SOD for SignerInfo: {e}")

                logger.debug(f"Using DSC (pymrtd) for verification: type={type(dsc_pymrt)}")
                try:
                    logger.debug(
                        f"DSC cross-check: subject={dsc_cert.subject.rfc4514_string()}, serial={dsc_cert.serial_number}, pub_key_type={type(dsc_cert.public_key())}, sig_algo_oid={getattr(dsc_cert.signature_algorithm_oid, 'dotted_string', dsc_cert.signature_algorithm_oid)}"
                    )
                except Exception as e:
                    logger.debug(f"Could not emit DSC cross-check info: {e}")

                try:
                    sod_obj.verify(si, dsc_pymrt)
                    sod_signature_valid = True
                    logger.debug("SOD signature verified successfully by pymrtd.")
                except Exception as e:
                    logger.warning(f"pymrtd sod_obj.verify() failed: {e}", exc_info=True)
                    sod_signature_valid = False
            except Exception as e:
                logger.warning(f"SOD verification preparation failed: {e}", exc_info=True)
                sod_signature_valid = False

        # 5) Verify DG1 Hash
        dg1_sha256_hex = hashlib.sha256(dg1_bytes).hexdigest()
        dg1_expected_hash_hex = ""
        try:
            dg1_expected_hash_hex = ""
            lds = sod_obj.ldsSecurityObject
            dg_hashes = getattr(lds, "dgHashes", None)
            if dg_hashes is None:
                dg_hashes = getattr(lds, "dataGroupHashValues", None) or []

            for dg in dg_hashes:
                try:
                    num = None
                    if hasattr(dg, "number"):
                        num_attr = dg.number
                        if hasattr(num_attr, "value"):
                            num = num_attr.value
                        elif hasattr(num_attr, "native"):
                            num = num_attr.native
                        else:
                            try:
                                num = int(num_attr)
                            except Exception:
                                num = None
                    if num == 1:
                        if hasattr(dg, "hash"):
                            dg1_expected_hash_hex = dg.hash.hex()
                        else:
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
        if not dg1_matches and len(dg1_expected_hash_hex) == 40:
            dg1_matches = (dg1_expected_hash_hex == hashlib.sha1(dg1_bytes).hexdigest())

        # 6) Final verdict and response
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
                },
            },
        }