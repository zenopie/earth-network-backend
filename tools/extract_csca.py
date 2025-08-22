# /tools/extract_csca.py
from __future__ import annotations

from typing import List

from asn1crypto import cms, core as asn1
import asn1crypto.x509 as asn1x509

import os
import tempfile
import urllib.request
import shutil
import logging

def _der_from_cert_choice(cert_choice) -> bytes:
    """
    Normalize various ASN.1 representations to DER certificate bytes.
    Supports:
      - CertificateChoices with .dump()
      - CertificateChoices with .chosen.dump()
      - Native tuple form: ('certificate', <Certificate>)
      - Raw bytes
    """
    # Direct ASN.1 object with dump()
    if hasattr(cert_choice, "dump"):
        try:
            return cert_choice.dump()
        except Exception:
            pass
    # CertificateChoices with chosen.dump()
    if hasattr(cert_choice, "chosen") and hasattr(cert_choice.chosen, "dump"):
        try:
            return cert_choice.chosen.dump()
        except Exception:
            pass
    # Sometimes asn1crypto yields native tuples like ('certificate', <Certificate>)
    if isinstance(cert_choice, tuple) and len(cert_choice) == 2:
        _, val = cert_choice
        if hasattr(val, "dump"):
            try:
                return val.dump()
            except Exception:
                pass
        if hasattr(val, "chosen") and hasattr(val.chosen, "dump"):
            try:
                return val.chosen.dump()
            except Exception:
                pass
        if isinstance(val, (bytes, bytearray)):
            return val
        try:
            return bytes(val)
        except Exception:
            pass
    # Raw bytes directly
    if isinstance(cert_choice, (bytes, bytearray)):
        return cert_choice
    # Last resort attempt
    try:
        return bytes(cert_choice)
    except Exception:
        raise ValueError("Unsupported certificate choice type for DER extraction")


def _scan_der_certs(data: bytes) -> List[bytes]:
    """
    Brute-force scan a byte blob for DER-encoded X.509 Certificates.
    Uses asn1crypto.x509.Certificate.load to validate chunks.
    """
    res: List[bytes] = []
    i = 0
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0x30:  # SEQUENCE
            i += 1
            continue
        if i + 2 > n:
            break
        b1 = data[i + 1]
        if b1 & 0x80:
            num_len_bytes = b1 & 0x7F
            if num_len_bytes == 0 or i + 2 + num_len_bytes > n:
                i += 1
                continue
            length = int.from_bytes(data[i + 2:i + 2 + num_len_bytes], "big")
            header_len = 2 + num_len_bytes
        else:
            length = b1
            header_len = 2
        total = header_len + length
        if total <= 0 or i + total > n:
            i += 1
            continue
        chunk = data[i:i + total]
        try:
            asn1x509.Certificate.load(chunk)
            res.append(chunk)
            i += total
            continue
        except Exception:
            i += 1
    return res


def extract_csca_ders(ml_bytes: bytes) -> List[bytes]:
    """
    Extract DER-encoded CSCA certificates from an ICAO Master List (.ml) without verifying the ML.
    Returns a list of DER certificate bytes.
    """
    # Load the outer CMS
    content_info = cms.ContentInfo.load(ml_bytes)
    if content_info["content_type"].native != "signed_data":
        raise ValueError("Not a CMS SignedData")

    sd = content_info["content"]
    encap = sd["encap_content_info"]

    # ICAO id-icao-cscaMasterList OID (Doc 9303)
    ID_ICAO_CSCA_MASTERLIST = "2.23.136.1.1.2"

    # Liberal in what we accept: CertificateChoices for cert list entries
    class ML_CertList(asn1.SetOf):
        _child_spec = cms.CertificateChoices

    class ML_CscaList(asn1.Sequence):
        _fields = [
            ("version", asn1.Integer),
            ("certList", ML_CertList),
        ]

    # Register mapping BEFORE parse so EncapsulatedContentInfo decodes the content automatically
    cms.ContentType._map[ID_ICAO_CSCA_MASTERLIST] = "icaoCscaMasterList"
    cms.EncapsulatedContentInfo._oid_specs["icaoCscaMasterList"] = ML_CscaList  # type: ignore[index]

    # Re-load with mapping applied
    content_info2 = cms.ContentInfo.load(ml_bytes)
    if content_info2["content_type"].native != "signed_data":
        raise ValueError("Not a CMS SignedData (2)")

    sd2 = content_info2["content"]
    encap2 = sd2["encap_content_info"]

    # content may be ML_CscaList or a ParsableOctetString that can be parsed
    e2 = encap2["content"]

    # Obtain ML_CscaList from 'content'
    try:
        if hasattr(e2, "parse"):
            csca_list = e2.parse(ML_CscaList)
        elif hasattr(e2, "parsed") and e2.parsed is not None:
            csca_list = e2.parsed
        else:
            if hasattr(e2, "native") and isinstance(e2.native, (bytes, bytearray)):
                ml_inner2 = e2.native
            elif hasattr(e2, "dump"):
                ml_inner2 = e2.dump()
            elif isinstance(e2, (bytes, bytearray)):
                ml_inner2 = e2
            else:
                ml_inner2 = bytes(e2)
            csca_list = ML_CscaList.load(ml_inner2)
    except Exception:
        if hasattr(e2, "native") and isinstance(e2.native, (bytes, bytearray)):
            csca_list = ML_CscaList.load(e2.native)
        else:
            raise

    ders: List[bytes] = []
    for cert_choice in csca_list["certList"]:
        try:
            der = _der_from_cert_choice(cert_choice)
            # Optional minimal sanity check
            asn1x509.Certificate.load(der)
            ders.append(der)
        except Exception:
            # Skip malformed entries liberally
            continue

    # Fallbacks if nothing was extracted
    if not ders:
        # Try SignedData.certificates
        try:
            certs_field = sd["certificates"]
        except KeyError:
            certs_field = []
        for cert_choice in certs_field:
            if getattr(cert_choice, "name", None) != "certificate":
                continue
            try:
                der = _der_from_cert_choice(cert_choice)
                asn1x509.Certificate.load(der)
                ders.append(der)
            except Exception:
                continue

    if not ders:
        ders.extend(_scan_der_certs(ml_bytes))

    return ders


def _safe_filename(s: str) -> str:
    """Create a filesystem-friendly filename from a string."""
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in s)[:200]


def save_ders_to_dir(ders: List[bytes], dest_dir: str, prefix: str = "csca") -> int:
    """
    Persist DER certificates to dest_dir with stable filenames.
    Returns the number of certificates written.
    """
    from cryptography import x509  # lazy import to avoid hard dependency until used

    os.makedirs(dest_dir, exist_ok=True)
    count = 0
    for idx, cert_der in enumerate(ders, 1):
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            subj_safe = _safe_filename(cert.subject.rfc4514_string())
            out_name = f"{prefix}_{idx:04d}_{subj_safe}.der"
            with open(os.path.join(dest_dir, out_name), "wb") as cf:
                cf.write(cert_der)
            count += 1
        except Exception as e:
            logging.warning(f"Skipping CSCA certificate: {e}")
    return count


def download_and_extract_csca(url: str, dest_dir: str) -> str:
    """
    Download a Master List from url and extract CSCA DER files into dest_dir/certs.
    Returns dest_dir.
    """
    os.makedirs(dest_dir, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp()
    os.close(tmp_fd)
    try:
        with urllib.request.urlopen(url) as resp, open(tmp_path, "wb") as out:
            shutil.copyfileobj(resp, out)

        fname = os.path.basename(urllib.request.urlparse(url).path) or "csca_masterlist.ml"
        target = os.path.join(dest_dir, fname)
        shutil.move(tmp_path, target)

        if fname.lower().endswith(".ml"):
            with open(target, "rb") as f:
                ml_bytes = f.read()

            ders = extract_csca_ders(ml_bytes)

            certs_dir = os.path.join(dest_dir, "certs")
            os.makedirs(certs_dir, exist_ok=True)
            extracted = save_ders_to_dir(ders, certs_dir, prefix="csca")
            logging.info(f"Extracted {extracted} CSCA certificates via tools.extract_csca")
        else:
            logging.info(f"Downloaded non-.ml file '{fname}' to {dest_dir} (no extraction)")

        return dest_dir
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)