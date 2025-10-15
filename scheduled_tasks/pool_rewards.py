# /scheduled_tasks/pool_rewards.py
"""
Scheduled task to update pool rewards daily.
This task calls the update_pool_rewards function on the unified pool contract.
"""
import logging
from secret_sdk.key.mnemonic import MnemonicKey
from secret_sdk.core.wasm import MsgExecuteContract

import config
from dependencies import get_async_secret_client

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def update_pool_rewards():
    """
    Updates pool rewards by calling update_pool_rewards on the unified pool contract.
    This function is designed to be called by the scheduler only.
    Scheduled to run daily.
    """
    try:
        logger.info("[PoolRewards] Starting daily update_pool_rewards job...")

        # Get async client
        secret_async_client = await get_async_secret_client()

        # Create wallet
        async_wallet = secret_async_client.wallet(MnemonicKey(config.WALLET_KEY))

        # Create the MsgExecuteContract instance
        execute_msg = MsgExecuteContract(
            sender=async_wallet.key.acc_address,
            contract_address=config.UNIFIED_POOL_CONTRACT,
            code_hash=config.UNIFIED_POOL_HASH,
            msg={
                "update_pool_rewards": {},
            },
        )

        # Broadcast the transaction
        tx = await async_wallet.create_and_broadcast_tx(
            msg_list=[execute_msg],
            gas=1_000_000,
            memo="Scheduled pool rewards update"
        )

        if tx.code != 0:
            logger.error(f"[PoolRewards] Transaction failed: {tx.raw_log}")
            raise Exception(f"Transaction failed: {tx.raw_log}")

        logger.info(f"[PoolRewards] Successfully updated pool rewards. Tx hash: {tx.txhash}")
        return {"success": True, "tx_hash": tx.txhash}

    except Exception as e:
        logger.error(f"[PoolRewards] Error updating pool rewards: {e}", exc_info=True)
        raise
