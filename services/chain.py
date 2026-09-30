"""Sending dust on the earth chain.

Dust rather than a fee grant, deliberately. A fee grant only covers the fee, and
the fee is not the whole problem: an address with no on-chain account cannot
produce a valid signature at all, because the ante handler rejects an unknown
signer before it ever looks at who is paying. A plain bank send materialises the
account and funds it in one transaction.
"""
import asyncio
import logging

import requests

from cosmpy.aerial.client import LedgerClient, NetworkConfig
from cosmpy.aerial.exceptions import BroadcastError, QueryTimeoutError
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
    _bound_http(_client)
    logger.info("gas-grant wallet %s on %s", _wallet.address(), config.EARTH_CHAIN_ID)


def _bound_http(client: LedgerClient) -> None:
    """Gives every REST call the client makes a timeout.

    cosmpy's RestClient uses a bare requests session, which waits forever. Every
    send runs under _send_lock, so one request to a node that accepted the
    connection and never answered used to stop every payout behind it until the
    process was restarted. A gRPC endpoint has no session to bound and is left
    alone.
    """
    rest = getattr(client.bank, "_rest_api", None)
    if rest is None:
        return
    session = rest._session
    request = session.request

    def with_timeout(method, url, **kwargs):
        kwargs.setdefault("timeout", config.CHAIN_HTTP_TIMEOUT)
        return request(method, url, **kwargs)

    session.request = with_timeout


def wallet_address() -> str:
    if _wallet is None:
        raise RuntimeError("chain service not initialised")
    return str(_wallet.address())


def balance() -> int:
    """The hot wallet's uerth balance, for the health endpoint."""
    if _client is None or _wallet is None:
        raise RuntimeError("chain service not initialised")
    return _client.query_bank_balance(_wallet.address(), config.EARTH_DENOM)


class SendUnresolved(Exception):
    """The send was broadcast and its outcome is not known.

    The difference from an ordinary failure is what the caller may do about it.
    A send that failed did not move coins, so the grant id that paid for it can
    be handed back. A send whose outcome is unknown may well have landed, and
    handing the id back would let the same grant be paid twice.
    """

    def __init__(self, tx_hash: str, cause: Exception) -> None:
        super().__init__(f"tx {tx_hash} was broadcast but not confirmed: {cause}")
        self.tx_hash = tx_hash


async def send_dust(address: str) -> str:
    """Sends DUST_UERTH to address. Returns the tx hash.

    Runs the blocking cosmpy call on a worker thread so the event loop keeps
    serving callbacks, but holds the lock across it so sends stay serialised.

    Raises SendUnresolved when the transaction reached the chain but its result
    could not be read, and an ordinary exception when it demonstrably did not
    move any coins.
    """
    if _client is None or _wallet is None:
        raise RuntimeError("chain service not initialised")

    destination = Address(address)  # raises on a malformed bech32 address

    async with _send_lock:
        return await asyncio.to_thread(_send_blocking, destination)


def _send_blocking(destination: Address) -> str:
    # Broadcast. send_tokens looks up the account, simulates, and posts the
    # transaction, and a network fault in the post can come after the node has
    # accepted it. Only a connection that was never made proves nothing went
    # out; any other transport failure — a read timeout above all, which the
    # timeout on the session now makes a real possibility — is treated as
    # unresolved, so the caller keeps the id and Google's retry is not paid a
    # second time. Errors that are not transport errors (a rejected
    # transaction, a signing failure) moved nothing and propagate as they are.
    try:
        tx = _client.send_tokens(destination, config.DUST_UERTH, config.EARTH_DENOM, _wallet)
    except requests.exceptions.ConnectTimeout:
        raise
    except requests.exceptions.ConnectionError as exc:
        if _never_connected(exc):
            raise
        raise SendUnresolved("", exc) from exc
    except requests.exceptions.RequestException as exc:
        raise SendUnresolved("", exc) from exc
    tx_hash = str(tx.tx_hash)

    try:
        tx.wait_to_complete()
    except BroadcastError:
        # The transaction was included and failed — out of gas, insufficient
        # fees, or a dry hot wallet, which is the common one. It consumed a
        # sequence number and moved no coins, so the grant id is genuinely
        # unspent and the caller may hand it back.
        raise
    except QueryTimeoutError as exc:
        # Polling gave up. The transaction may still be sitting in a mempool and
        # may still land. Only the caller can decide what to do, and what it
        # must not do is release the id.
        raise SendUnresolved(tx_hash, exc) from exc
    except Exception as exc:
        # An unrecognised failure while querying is the same situation: the
        # transaction is out of our hands and its fate is unknown. Fail into the
        # cautious branch rather than the convenient one.
        raise SendUnresolved(tx_hash, exc) from exc

    return tx_hash


def _never_connected(exc: requests.exceptions.ConnectionError) -> bool:
    """Whether a connection error happened before any bytes were sent.

    Refused and unresolvable connections surface as a NewConnectionError inside
    the urllib3 MaxRetryError that requests wraps; anything else — a reset or
    a dropped connection mid-exchange — may have happened after the node read
    the request.
    """
    from urllib3.exceptions import NameResolutionError, NewConnectionError

    reason = getattr(exc.args[0], "reason", None) if exc.args else None
    return isinstance(reason, (NewConnectionError, NameResolutionError))
