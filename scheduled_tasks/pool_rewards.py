# /scheduled_tasks/pool_rewards.py
"""
Scheduled task to update pool rewards daily.
This task calls the update_pool_rewards function on the unified pool contract.
"""
from secret_sdk.client.lcd import AsyncLCDClient
from secret_sdk.key.mnemonic import MnemonicKey
from secret_sdk.core.wasm import MsgExecuteContract

import config
from dependencies import secret_client

async def update_pool_rewards():
    """
    Updates pool rewards by calling update_pool_rewards on the unified pool contract.
    This function is designed to be called by the scheduler only.
    Scheduled to run daily.
    """
    try:
        print("[PoolRewards] Starting daily update_pool_rewards job...", flush=True)

        # Create async client
        async with AsyncLCDClient(chain_id=config.SECRET_CHAIN_ID, url=config.SECRET_LCD_URL) as secret_async_client:
            # Create wallet
            async_wallet = secret_async_client.wallet(MnemonicKey(config.WALLET_KEY))

            # Create the MsgExecuteContract instance
            execute_msg = MsgExecuteContract(
                sender=async_wallet.key.acc_address,
                contract=config.UNIFIED_POOL_CONTRACT,
                msg={"update_pool_rewards": {}},
                code_hash=config.UNIFIED_POOL_HASH,
                encryption_utils=secret_client.encrypt_utils,
            )

            # Broadcast the transaction
            tx = await async_wallet.create_and_broadcast_tx(
                msg_list=[execute_msg],
                gas=1_000_000,
                memo="Scheduled pool rewards update"
            )

            if tx.code != 0:
                print(f"[PoolRewards] ❌ Transaction failed: {tx.raw_log}", flush=True)
                raise Exception(f"Transaction failed: {tx.raw_log}")

            print(f"[PoolRewards] ✅ Successfully updated pool rewards. Tx hash: {tx.txhash}", flush=True)
            return {"success": True, "tx_hash": tx.txhash}

    except Exception as e:
        print(f"[PoolRewards] ❌ Error updating pool rewards: {e}", flush=True)
        raise
