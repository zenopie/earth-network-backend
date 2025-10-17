"""
Contract Registry Loader

Fetches contract addresses and code hashes from the on-chain registry contract.
This replaces hardcoded values in config.py with dynamically loaded values.
"""
import logging
from typing import Dict, Any
from secret_sdk.client.lcd import LCDClient

logger = logging.getLogger(__name__)

# Registry contract constants
REGISTRY_CONTRACT = "secret1ql943kl7fd7pyv9njf7rmngxhzljncgx6eyw5j"
REGISTRY_HASH = "2a53df1dc1d8f37ecddd9463930c9caa4940fed94f9a8cd113d6285eef09445b"


class RegistryData:
    """Singleton to store registry data loaded from the contract."""

    def __init__(self):
        self.contracts: Dict[str, Dict[str, str]] = {}
        self.tokens: Dict[str, Dict[str, str]] = {}
        self.loaded = False

    def get_contract(self, name: str) -> Dict[str, str]:
        """Get contract info by name."""
        if not self.loaded:
            raise RuntimeError("Registry not loaded. Call load_registry() first.")
        return self.contracts.get(name, {})

    def get_token(self, symbol: str) -> Dict[str, str]:
        """Get token contract info by symbol."""
        if not self.loaded:
            raise RuntimeError("Registry not loaded. Call load_registry() first.")
        return self.tokens.get(symbol, {})


# Global registry data instance
registry_data = RegistryData()


def load_registry(lcd_url: str, chain_id: str) -> RegistryData:
    """
    Query the contract registry and populate the global registry_data.

    Args:
        lcd_url: Secret Network LCD URL
        chain_id: Secret Network chain ID

    Returns:
        The populated RegistryData instance

    Raises:
        Exception: If registry query fails
    """
    logger.info("Loading contract registry from on-chain...")

    try:
        # Create LCD client
        client = LCDClient(url=lcd_url, chain_id=chain_id)

        # Query the registry
        response = client.wasm.contract_query(
            REGISTRY_CONTRACT,
            {"get_all_contracts": {}},
            REGISTRY_HASH
        )

        if not response or "contracts" not in response:
            raise ValueError("Invalid registry response format")

        # Parse and organize the registry data
        contracts = {}
        tokens = {}

        logger.info("Parsing registry response...")
        for item in response["contracts"]:
            contract_info = {
                "contract": item["info"]["address"],
                "hash": item["info"]["code_hash"]
            }

            name = item["name"]
            logger.info(f"  Found: '{name}' -> {contract_info['contract']}")

            # Categorize as token or contract based on name
            if "token" in name.lower():
                # Extract token symbol (e.g., "erth_token" -> "ERTH")
                token_symbol = name.replace("_token", "").replace("_Token", "").upper()
                tokens[token_symbol] = contract_info
                logger.info(f"    -> Categorized as TOKEN: {token_symbol}")
            else:
                # Store contract by its registry name
                contracts[name] = contract_info
                logger.info(f"    -> Categorized as CONTRACT: {name}")

        # Update global registry data
        registry_data.contracts = contracts
        registry_data.tokens = tokens
        registry_data.loaded = True

        logger.info(f"Registry loaded: {len(contracts)} contracts, {len(tokens)} tokens")
        return registry_data

    except Exception as e:
        logger.error(f"Failed to load contract registry: {e}")
        raise


def get_registry() -> RegistryData:
    """
    Get the global registry data instance.

    Returns:
        The RegistryData instance

    Raises:
        RuntimeError: If registry hasn't been loaded yet
    """
    if not registry_data.loaded:
        raise RuntimeError(
            "Registry not loaded. Call load_registry() during application startup."
        )
    return registry_data
