"""Sending dust on the earth chain.

Dust rather than a fee grant, deliberately. A fee grant only covers the fee, and
the fee is not the whole problem: an address with no on-chain account cannot
produce a valid signature at all, because the ante handler rejects an unknown
signer before it ever looks at who is paying. A plain bank send materialises the
account and funds it in one transaction.
"""
import asyncio
import logging

from cosmpy.aerial.client import LedgerClient, NetworkConfig
from cosmpy.aerial.wallet import LocalWallet
from cosmpy.crypto.address import Address

import config

logger = logging.getLogger(__name__)

_client: LedgerClient | None = None
_wallet: LocalWallet | None = None

# Every send goes through one lock. The hot key has a single account sequence,
# and concurrent callbacks would otherwise race to reuse it and fail with a
# sequence mismatch — which is what the old backend's transaction queue existed
# to prevent.
_send_lock = asyncio.Lock()


def _network() -> NetworkConfig:
    return NetworkConfig(
        chain_id=config.EARTH_CHAIN_ID,
        url=config.EARTH_NODE_URL,
        fee_minimum_gas_price=config.EARTH_GAS_PRICE,
        fee_denomination=config.EARTH_DENOM,
        staking_denomination=config.EARTH_DENOM,
        faucet_url=None,
    )


def init() -> None:
    """Builds the client and hot wallet. Raises if the mnemonic is missing."""
    global _client, _wallet
    if not config.GAS_WALLET_MNEMONIC:
        raise RuntimeError("GAS_WALLET_MNEMONIC is unset; refusing to start")
    _wallet = LocalWallet.from_mnemonic(config.GAS_WALLET_MNEMONIC, prefix=config.EARTH_PREFIX)
    _client = LedgerClient(_network())
    logger.info("ads-for-gas wallet %s on %s", _wallet.address(), config.EARTH_CHAIN_ID)


def wallet_address() -> str:
    if _wallet is None:
        raise RuntimeError("chain service not initialised")
    return str(_wallet.address())


def balance() -> int:
    """The hot wallet's uerth balance, for the health endpoint."""
    if _client is None or _wallet is None:
        raise RuntimeError("chain service not initialised")
    return _client.query_bank_balance(_wallet.address(), config.EARTH_DENOM)


async def send_dust(address: str) -> str:
    """Sends DUST_UERTH to address. Returns the tx hash.

    Runs the blocking cosmpy call on a worker thread so the event loop keeps
    serving callbacks, but holds the lock across it so sends stay serialised.
    """
    if _client is None or _wallet is None:
        raise RuntimeError("chain service not initialised")

    destination = Address(address)  # raises on a malformed bech32 address

    async with _send_lock:
        return await asyncio.to_thread(_send_blocking, destination)


def _send_blocking(destination: Address) -> str:
    tx = _client.send_tokens(destination, config.DUST_UERTH, config.EARTH_DENOM, _wallet)
    tx.wait_to_complete()
    return str(tx.tx_hash)
