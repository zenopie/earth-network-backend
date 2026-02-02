# /scheduled_tasks/pool_rewards.py
"""
Scheduled task to update pool rewards daily.
This task calls the update_pool_rewards function on the unified pool contract.
"""
from secret_sdk.core.wasm import MsgExecuteContract

import config
from services.tx_queue import get_tx_queue


async def update_pool_rewards():
    """
    Updates pool rewards by calling update_pool_rewards on the unified pool contract.
    This function is designed to be called by the scheduler only.
    Scheduled to run daily.
    """
    try:
        print("[PoolRewards] Starting daily update_pool_rewards job...", flush=True)

        tx_queue = get_tx_queue()

        execute_msg = MsgExecuteContract(
            sender=tx_queue.wallet_address,
            contract=config.UNIFIED_POOL_CONTRACT,
            msg={"update_pool_rewards": {}},
            code_hash=config.UNIFIED_POOL_HASH,
            encryption_utils=tx_queue.encryption_utils,
        )

        tx_result = await tx_queue.submit(
            msg_list=[execute_msg],
            gas=1_000_000,
            memo="Scheduled pool rewards update"
        )

        if not tx_result.success:
            print(f"[PoolRewards] Transaction failed: {tx_result.error}", flush=True)
            raise Exception(f"Transaction failed: {tx_result.error}")

        print(f"[PoolRewards] Successfully updated pool rewards. Tx hash: {tx_result.tx_hash}", flush=True)
        return {"success": True, "tx_hash": tx_result.tx_hash}

    except Exception as e:
        print(f"[PoolRewards] Error updating pool rewards: {e}", flush=True)
        raise
