"""Paying gas grants from the hot wallet on the earth chain.

shield_dust: a MsgShield of the dust into the shielded pool, as a note owned
by whoever holds the opening of the pc the app sent. A private tx is unsigned
and pays its fee from a note, so a new human needs a note, not an account;
and the hot wallet learns only that some note was funded, never the key that
will spend it.
"""
import asyncio
import hashlib
import logging

import requests

from cosmpy.aerial.client import LedgerClient, NetworkConfig
from cosmpy.aerial.client.utils import prepare_basic_transaction
from cosmpy.aerial.exceptions import BroadcastError, QueryTimeoutError
from cosmpy.aerial.tx import Transaction
from cosmpy.aerial.tx_helpers import SubmittedTx
from cosmpy.aerial.wallet import LocalWallet

import config
from services import shielded_msg

logger = logging.getLogger(__name__)

_client: LedgerClient | None = None
_wallet: LocalWallet | None = None

# Every send goes through one lock. The hot key has a single account sequence,
# and concurrent sends would otherwise race to reuse it and fail with a
# sequence mismatch.
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
    connection and never answered would stop every payout behind it. A gRPC
    endpoint has no session to bound and is left alone.
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
        super().__init__(f"broadcast but not confirmed: {cause.__class__.__name__}")
        self.tx_hash = tx_hash


async def shield_dust(pc: bytes, ciphertext: bytes) -> str:
    """Shields DUST_UERTH from the hot wallet into a note to pc. Returns the tx hash.

    Runs the blocking cosmpy call on a worker thread so the event loop keeps
    serving, but holds the lock across it so sends stay serialised.

    Raises SendUnresolved when the transaction may
    have landed, an ordinary exception when it demonstrably moved nothing.
    """
    if len(ciphertext) != shielded_msg.BLIND_CIPHERTEXT_BYTES:
        raise ValueError(f"MsgShield needs a {shielded_msg.BLIND_CIPHERTEXT_BYTES}-byte ciphertext, got {len(ciphertext)}")
    if _client is None or _wallet is None:
        raise RuntimeError("chain service not initialised")
    async with _send_lock:
        return await asyncio.to_thread(_shield_blocking, pc, ciphertext)


def _shield_blocking(pc: bytes, ciphertext: bytes) -> str:
    tx = Transaction()
    tx.add_message(shielded_msg.build(str(_wallet.address()), config.DUST_UERTH, config.EARTH_DENOM, pc, ciphertext))
    # Account lookup, simulation and signing. Nothing has been broadcast yet,
    # so any failure here — a read timeout included — moved nothing.
    prepare_basic_transaction(_client, tx, _wallet)
    return _broadcast(lambda: _client.broadcast_tx(tx), tx_hash_of(tx))


def tx_hash_of(tx: Transaction) -> str:
    """The hash the chain will know the signed tx by: SHA-256 of its bytes."""
    return hashlib.sha256(tx.tx.SerializeToString()).hexdigest().upper()


def _broadcast(submit, tx_hash: str) -> str:
    """Posts a signed tx whose hash is already known, and waits for it.

    A failure in the post can come after the node has accepted it. Only two
    outcomes prove nothing went out: a connection that was never made, and
    the node's own CheckTx refusal (cosmpy's BroadcastError, raised from the
    node's answer — except "already in the mempool cache", which says the
    opposite). Every other exception — a read timeout, a dropped connection,
    and cosmpy's bare RuntimeError for any non-200 answer, which behind
    Cloudflare is a 502/504/524 that can arrive after the node took the tx
    (audit-4 B2) — may have landed. For those the chain is asked for the tx
    by its hash before giving up: found and successful is a success, found
    and failed moved nothing, not found is SendUnresolved carrying the hash.
    """
    try:
        submitted = submit()
    except requests.exceptions.ConnectTimeout:
        raise
    except requests.exceptions.ConnectionError as exc:
        if _never_connected(exc):
            raise
        return _resolve(SubmittedTx(_client, tx_hash), exc)
    except BroadcastError as exc:
        if _already_in_mempool(exc):
            return _resolve(SubmittedTx(_client, tx_hash), exc)
        raise
    except Exception as exc:
        return _resolve(SubmittedTx(_client, tx_hash), exc)
    return _resolve(submitted, None)


def _already_in_mempool(exc: BroadcastError) -> bool:
    """CheckTx code 19 (ErrTxInMempoolCache): this very tx is already pending."""
    return "tx already exists in cache" in str(exc) or "already in mempool" in str(exc)


def _resolve(submitted, cause: Exception | None) -> str:
    tx_hash = str(submitted.tx_hash)
    try:
        submitted.wait_to_complete()
    except BroadcastError:
        # Included and failed — out of gas, insufficient fees, or a dry hot
        # wallet, the common one. It consumed a sequence number and moved no
        # coins, so the grant id is genuinely unspent and may be handed back.
        raise
    except QueryTimeoutError as exc:
        # Not seen within the wait. It may still be in a mempool and may still
        # land; the caller must not release the id.
        raise SendUnresolved(tx_hash, cause or exc) from exc
    except Exception as exc:
        # An unrecognised failure while querying: the fate is unknown. Fail
        # into the cautious branch rather than the convenient one.
        raise SendUnresolved(tx_hash, cause or exc) from exc
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
