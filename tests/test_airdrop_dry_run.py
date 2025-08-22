# /tests/test_airdrop_dry_run.py

from __future__ import annotations

import json
import pytest
import requests

from secret_sdk.client.lcd import LCDClient
import config
from routers import airdrop


def _get_first_validator_operator_address(client: LCDClient) -> str:
    """
    Use raw LCD HTTP (requests) to get the first validator operator address.
    This avoids sync/async mismatches in secret_sdk internals during tests.
    """
    url = f"{config.SECRET_LCD_URL.rstrip('/')}/cosmos/staking/v1beta1/validators"
    try:
        r = requests.get(url, params={"pagination.limit": "1"}, timeout=15)
        r.raise_for_status()
        data = r.json()
        vals = data.get("validators") or []
    except Exception as e:
        pytest.skip(f"Failed to fetch validators from LCD: {e}")

    if not vals:
        pytest.skip("No validators returned by LCD")
    first = vals[0]
    op = first.get("operator_address")
    if not op:
        pytest.skip("Validator missing operator_address")
    return op


@pytest.mark.integration
def test_airdrop_dry_run_first_validator():
    client = LCDClient(url=config.SECRET_LCD_URL, chain_id=config.SECRET_CHAIN_ID)
    op_addr = _get_first_validator_operator_address(client)

    # Override validator for this test
    config.MERKLE_VALIDATOR = op_addr

    try:
        meta = airdrop.run_merkle_job(verbose=True)
    except RuntimeError as e:
        if "No balances aggregated" in str(e):
            pytest.skip(f"First validator has no delegations for denom {config.MERKLE_DENOM}")
        raise

    assert isinstance(meta, dict)
    assert meta.get("merkle_root", "").startswith("0x")
    assert len(meta.get("merkle_root")) == 66  # 0x + 64 hex chars
    assert meta.get("validator_address") == op_addr
    assert meta.get("denom") == getattr(config, "MERKLE_DENOM", "uscrt")
    assert int(meta.get("total_addresses", 0)) >= 1

    # Optional: print meta for logs
    print(json.dumps(meta, indent=2))