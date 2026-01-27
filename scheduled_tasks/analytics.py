# /scheduled_tasks/analytics.py
"""
Scheduled task to update analytics data hourly.
Fetches token prices, pool reserves, and calculates ERTH price and TVL.
Uses SQLite for persistent storage.
"""
import os
import json
import time
import math
import aiohttp
import sqlite3
import traceback
from typing import List, Dict, Any, Optional

import config
from dependencies import secret_client

# --- Database Configuration ---
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "analytics.db")


def _get_conn() -> sqlite3.Connection:
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_analytics_db() -> None:
    """Initialize the analytics database schema."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS analytics_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER UNIQUE NOT NULL,
                erth_price REAL NOT NULL,
                erth_total_supply REAL NOT NULL,
                erth_market_cap REAL NOT NULL,
                tvl REAL NOT NULL,
                anml_price REAL NOT NULL,
                anml_total_supply REAL NOT NULL,
                anml_market_cap REAL NOT NULL,
                scrt_price REAL NOT NULL,
                pools_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_data(timestamp)")
        conn.commit()
    finally:
        conn.close()


def _insert_data_point(data_point: Dict[str, Any]) -> bool:
    """
    Insert a new analytics data point into the database.
    Returns True if inserted, False if duplicate timestamp exists.
    """
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO analytics_data (
                timestamp, erth_price, erth_total_supply, erth_market_cap,
                tvl, anml_price, anml_total_supply, anml_market_cap,
                scrt_price, pools_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data_point["timestamp"],
                data_point["erthPrice"],
                data_point["erthTotalSupply"],
                data_point["erthMarketCap"],
                data_point["tvl"],
                data_point["anmlPrice"],
                data_point["anmlTotalSupply"],
                data_point["anmlMarketCap"],
                data_point["scrtPrice"],
                json.dumps(data_point["pools"]),
            ),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def _row_to_data_point(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a database row to an analytics data point dict."""
    return {
        "timestamp": row["timestamp"],
        "erthPrice": row["erth_price"],
        "erthTotalSupply": row["erth_total_supply"],
        "erthMarketCap": row["erth_market_cap"],
        "tvl": row["tvl"],
        "pools": json.loads(row["pools_json"]),
        "anmlPrice": row["anml_price"],
        "anmlTotalSupply": row["anml_total_supply"],
        "anmlMarketCap": row["anml_market_cap"],
        "scrtPrice": row["scrt_price"],
    }


def get_analytics_history() -> List[Dict[str, Any]]:
    """Returns the full analytics history from the database."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM analytics_data ORDER BY timestamp ASC")
        rows = cur.fetchall()
        return [_row_to_data_point(row) for row in rows]
    finally:
        conn.close()


def get_latest_data_point() -> Optional[Dict[str, Any]]:
    """Returns the most recent analytics data point, or None if no data."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM analytics_data ORDER BY timestamp DESC LIMIT 1")
        row = cur.fetchone()
        return _row_to_data_point(row) if row else None
    finally:
        conn.close()

# --- Core Analytics Logic ---

async def update_analytics_job():
    """
    The main job to be run by the scheduler. It fetches all necessary data
    to build and save a new analytics data point using the correct logic.
    """
    try:
        # 1. Fetch prices from CoinGecko
        token_ids_to_fetch = [t["coingeckoId"] for t in config.TOKENS.values() if "coingeckoId" in t]
        coingecko_ids_str = ",".join(token_ids_to_fetch)
        price_url = f"https://api.coingecko.com/api/v3/simple/price?ids={coingecko_ids_str}&vs_currencies=usd"

        prices = {}
        async with aiohttp.ClientSession() as session:
            async with session.get(price_url) as resp:
                resp.raise_for_status()
                price_data = await resp.json()
                for symbol, token_info in config.TOKENS.items():
                    if "coingeckoId" in token_info and token_info["coingeckoId"] in price_data:
                        prices[symbol] = price_data[token_info["coingeckoId"]]["usd"]

        # 2. Query token total supplies
        erth_info = secret_client.wasm.contract_query(config.TOKENS['ERTH']['contract'], {"token_info": {}})
        erth_total_supply = int(erth_info["token_info"]["total_supply"]) / (10**config.TOKENS['ERTH']['decimals'])
        anml_info = secret_client.wasm.contract_query(config.TOKENS['ANML']['contract'], {"token_info": {}})
        anml_total_supply = int(anml_info["token_info"]["total_supply"]) / (10**config.TOKENS['ANML']['decimals'])

        # 3. Query the unified pool for reserves
        pool_addresses = [t["contract"] for k, t in config.TOKENS.items() if k != "ERTH"]
        unified_pool_res = secret_client.wasm.contract_query(config.UNIFIED_POOL_CONTRACT, {"query_pool_info": {"pools": pool_addresses}})

        # 4. First Pass: Collect pool data and calculate ERTH price weighted by ERTH liquidity depth
        total_weighted_price = 0
        total_erth_liquidity = 0  # Weight by ERTH reserves, not TVL
        total_tvl = 0
        external_price_pools = []  # Pools with coingecko prices (SSCRT, XMR, etc.)
        anml_data = None

        for i, pool_state in enumerate(unified_pool_res):
            token_symbol = list(config.TOKENS.keys())[i + 1]  # Skips ERTH
            token_meta = config.TOKENS[token_symbol]
            erth_reserve = int(pool_state["state"]["erth_reserve"]) / (10**config.TOKENS['ERTH']['decimals'])
            token_reserve = int(pool_state["state"]["token_b_reserve"]) / (10**token_meta['decimals'])

            if token_symbol == "ANML":
                anml_data = {"token_reserve": token_reserve, "erth_reserve": erth_reserve}
            elif token_symbol in prices:
                # Pools with external price feeds (SSCRT, XMR, etc.)
                pool_erth_price = (token_reserve / erth_reserve) * prices[token_symbol] if erth_reserve > 0 else 0
                pool_tvl = (token_reserve * prices[token_symbol]) + (erth_reserve * pool_erth_price)

                # Weight by ERTH liquidity depth
                total_weighted_price += pool_erth_price * erth_reserve
                total_erth_liquidity += erth_reserve
                total_tvl += pool_tvl

                external_price_pools.append({
                    "token": token_symbol,
                    "erthPrice": pool_erth_price,
                    "tvl": pool_tvl,
                    "erth_reserve": erth_reserve,
                    "token_reserve": token_reserve,
                    "token_usd_price": prices[token_symbol],
                })

        # 5. Calculate the global ERTH price (weighted by ERTH liquidity depth)
        global_erth_price = total_weighted_price / total_erth_liquidity if total_erth_liquidity > 0 else 0

        # 6. Second Pass: Calculate arbitrage depth for each external price pool
        all_pool_data = []
        for pool in external_price_pools:
            arb_depth = 0
            if global_erth_price > 0 and pool["erth_reserve"] > 0:
                k = pool["erth_reserve"] * pool["token_reserve"]
                target_erth_reserve = math.sqrt(k * pool["token_usd_price"] / global_erth_price)
                arb_depth = pool["erth_reserve"] - target_erth_reserve

            all_pool_data.append({
                "token": pool["token"],
                "erthPrice": pool["erthPrice"],
                "tvl": pool["tvl"],
                "arbDepth": arb_depth,
            })

        # 7. Calculate ANML price and TVL using the global ERTH price
        anml_price_final = 0
        if anml_data:
            anml_price_final = (anml_data["erth_reserve"] / anml_data["token_reserve"]) * global_erth_price if anml_data["token_reserve"] > 0 else 0
            anml_tvl = (anml_data["token_reserve"] * anml_price_final) + (anml_data["erth_reserve"] * global_erth_price)
            total_tvl += anml_tvl
            all_pool_data.append({"token": "ANML", "erthPrice": global_erth_price, "tvl": anml_tvl, "arbDepth": 0})

        # 8. Assemble the final data point
        now_utc_hour_start = int(time.time() // 3600 * 3600 * 1000)

        data_point = {
            "timestamp": now_utc_hour_start,
            "erthPrice": global_erth_price,
            "erthTotalSupply": erth_total_supply,
            "erthMarketCap": global_erth_price * erth_total_supply,
            "tvl": total_tvl,
            "pools": all_pool_data,
            "anmlPrice": anml_price_final,
            "anmlTotalSupply": anml_total_supply,
            "anmlMarketCap": anml_price_final * anml_total_supply,
            "scrtPrice": prices.get("SSCRT", 0),
        }

        # Insert into database (INSERT OR IGNORE handles duplicates)
        if _insert_data_point(data_point):
            print(f"[Analytics] Updated: ERTH=${global_erth_price:.4f}, TVL=${total_tvl:.0f}", flush=True)

    except Exception as e:
        print(f"[Analytics] Error: {e}", flush=True)
        traceback.print_exc()


async def init_analytics():
    """Initialize analytics on application startup."""
    init_analytics_db()
    latest = get_latest_data_point()
    is_stale = not latest or (time.time() - latest["timestamp"] / 1000) >= 3600
    if is_stale:
        await update_analytics_job()
    else:
        print(f"[Startup] Analytics: ERTH=${latest['erthPrice']:.4f}, TVL=${latest['tvl']:.0f}", flush=True)
