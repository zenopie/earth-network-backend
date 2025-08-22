# /tests/test_extract_csca.py
from __future__ import annotations

import importlib
from pathlib import Path
import sys

import pytest


def _has_cryptography() -> bool:
    try:
        from cryptography import x509  # noqa: F401
        return True
    except Exception:
        return False


@pytest.mark.integration
def test_extract_csca_from_local_masterlist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """
    Validate that config._download_and_extract_csca extracts CSCA DER files
    from the existing local ICAO Master List without verifying the ML.
    """
    # Ensure mandatory env vars so importing config doesn't fail
    monkeypatch.setenv("WALLET_KEY", "test")
    monkeypatch.setenv("SECRET_AI_API_KEY", "test")

    # Ensure project root is on sys.path for 'import config' inside containers
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    ml_path = Path(".csca_cache") / "allowlist.ml"
    if not ml_path.exists():
        pytest.skip("Local Master List not found at .csca_cache/allowlist.ml")

    if not _has_cryptography():
        pytest.skip("cryptography package not installed")

    # Import config after env vars are set
    import config  # noqa: WPS433
    importlib.reload(config)

    # Use file:// URL to feed local ML into the extractor
    ml_url = "file://" + str(ml_path.resolve())

    dest_dir = tmp_path / "ml_extract"
    dest_dir.mkdir(parents=True, exist_ok=True)

    out_dir = config._download_and_extract_csca(ml_url, str(dest_dir))  # noqa: SLF001
    certs_dir = Path(out_dir) / "certs"
    assert certs_dir.exists(), "Expected 'certs' directory to be created"

    der_files = sorted(
        [p for p in certs_dir.iterdir() if p.is_file() and p.suffix.lower() == ".der"]
    )
    assert len(der_files) > 0, "Expected at least one CSCA DER certificate to be extracted"

    # Emit a brief preview to test logs
    for p in der_files[:10]:
        print("DER:", p.name)