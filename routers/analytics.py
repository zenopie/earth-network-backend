# /routers/analytics.py
"""
Analytics API endpoints for ERTH Network.
Includes general analytics, pricing, CoinGecko-compliant DEX tickers, and supply data.
The scheduled analytics update job is in scheduled_tasks/analytics.py
"""
import time
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from secret_sdk.client.lcd import AsyncLCDClient

import config
from dependencies import get_async_secret_client
from scheduled_tasks.analytics import init_analytics, get_analytics_history, get_latest_data_point

logger = logging.getLogger(__name__)

router = APIRouter()


def _format_decimal(value: float) -> str:
    """Format a float as a decimal string, avoiding scientific notation."""
    if value == 0:
        return "0"
    return f"{value:.18f}".rstrip("0").rstrip(".")


@router.get("/analytics", summary="Get ERTH Analytics Data")
async def get_analytics():
    analytics_history = get_analytics_history()
    return {
        "latest": analytics_history[-1] if analytics_history else None,
        "history": analytics_history
    }

@router.get("/erth-price", summary="Get Current ERTH Price")
async def get_erth_price():
    """Get the current ERTH price in USD from the latest analytics data."""
    latest_data = get_latest_data_point()
    if not latest_data:
        return {"error": "No analytics data available"}

    return {
        "price": latest_data["erthPrice"],
        "timestamp": latest_data["timestamp"],
        "marketCap": latest_data["erthMarketCap"]
    }

@router.get("/anml-price", summary="Get Current ANML Price")
async def get_anml_price():
    """Get the current ANML price in USD from the latest analytics data."""
    latest_data = get_latest_data_point()
    if not latest_data:
        return {"error": "No analytics data available"}

    return {
        "price": latest_data["anmlPrice"],
        "timestamp": latest_data["timestamp"],
        "marketCap": latest_data["anmlMarketCap"]
    }


# --- CoinGecko-compliant DEX endpoints ---

@router.get("/tickers", summary="DEX Tickers")
async def get_tickers(
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client),
):
    """
    CoinGecko-compliant /tickers endpoint (DEX format).
    Returns 24-hour pricing, volume, and liquidity data for all trading pairs.
    All pairs have ERTH as the base currency.
    """
    erth_contract = config.TOKENS["ERTH"]["contract"]
    erth_decimals = config.TOKENS["ERTH"]["decimals"]

    if not erth_contract or not config.UNIFIED_POOL_CONTRACT:
        raise HTTPException(status_code=503, detail="Contracts not initialized")

    # Collect pool tokens (everything except ERTH)
    pool_tokens = {k: v for k, v in config.TOKENS.items() if k != "ERTH"}
    pool_addresses = [t["contract"] for t in pool_tokens.values()]

    # Query contract for current pool state and contract config
    try:
        pool_info_list = await secret_async_client.wasm.contract_query(
            config.UNIFIED_POOL_CONTRACT,
            {"query_pool_info": {"pools": pool_addresses}},
        )
        contract_config = await secret_async_client.wasm.contract_query(
            config.UNIFIED_POOL_CONTRACT,
            {"query_config": {}},
        )
    except Exception as e:
        logger.error("Failed to query exchange contract: %s", e)
        raise HTTPException(status_code=502, detail="Failed to query exchange contract")

    # Protocol fee for bid/ask spread (e.g. 50 = 0.5%)
    protocol_fee = int(contract_config.get("protocol_fee", "50"))
    fee_rate = protocol_fee / 10000

    # Get USD prices from latest analytics snapshot
    latest = get_latest_data_point()
    erth_price_usd = latest["erthPrice"] if latest else 0
    token_prices_usd = {}
    if latest and latest.get("pools"):
        for pool_data in latest["pools"]:
            token_prices_usd[pool_data["token"]] = pool_data.get("tokenPrice", 0)

    # Time calculations for 24h rolling volume approximation
    now = int(time.time())
    seconds_in_day = 86400
    current_day = now // seconds_in_day
    fraction_of_day = (now % seconds_in_day) / seconds_in_day

    tickers = []

    for i, (symbol, token_info) in enumerate(pool_tokens.items()):
        state = pool_info_list[i]["state"]
        token_b_contract = token_info["contract"]
        token_b_decimals = token_info["decimals"]

        # Parse reserves (adjusted for decimals)
        erth_reserve = int(state["erth_reserve"]) / (10**erth_decimals)
        token_b_reserve = int(state["token_b_reserve"]) / (10**token_b_decimals)

        if erth_reserve == 0:
            continue

        # Last price: price of 1 ERTH in Token_B terms
        last_price = token_b_reserve / erth_reserve

        # 24h rolling volume approximation from on-chain daily buckets.
        # daily_volumes[0] = current day (partial), [1] = previous day.
        # The array only rotates on swap, so check staleness.
        daily_volumes = [int(v) for v in state["daily_volumes"]]
        last_updated_day = int(state["last_updated_day"])
        days_stale = current_day - last_updated_day

        if days_stale == 0:
            # Current: today's partial + yesterday's remaining fraction
            volume_24h_raw = daily_volumes[0] + daily_volumes[1] * (1 - fraction_of_day)
        elif days_stale == 1:
            # Last swap was yesterday: use yesterday's volume for remaining fraction
            volume_24h_raw = daily_volumes[0] * (1 - fraction_of_day)
        else:
            # No swaps in 2+ days
            volume_24h_raw = 0

        # Volume is tracked in ERTH equivalent (raw units)
        base_volume = volume_24h_raw / (10**erth_decimals)
        target_volume = base_volume * last_price

        # Pool liquidity in USD
        token_usd = token_prices_usd.get(symbol, 0)
        liquidity_usd = (erth_reserve * erth_price_usd) + (token_b_reserve * token_usd)

        # Bid/Ask approximation for AMM (spread = protocol fee)
        bid = last_price * (1 - fee_rate)
        ask = last_price * (1 + fee_rate)

        tickers.append({
            "ticker_id": f"{erth_contract}_{token_b_contract}",
            "base_currency": erth_contract,
            "target_currency": token_b_contract,
            "pool_id": token_b_contract,
            "last_price": _format_decimal(last_price),
            "base_volume": _format_decimal(base_volume),
            "target_volume": _format_decimal(target_volume),
            "liquidity_in_usd": _format_decimal(liquidity_usd),
            "bid": _format_decimal(bid),
            "ask": _format_decimal(ask),
        })

    return tickers


# --- Token supply endpoints ---

async def _get_token_supply(symbol: str, secret_async_client: AsyncLCDClient) -> str:
    """Query on-chain total supply for a SNIP-20 token, returned with decimals."""
    token = config.TOKENS.get(symbol)
    if not token or not token["contract"]:
        raise HTTPException(status_code=503, detail=f"{symbol} contract not initialized")

    try:
        result = await secret_async_client.wasm.contract_query(
            token["contract"], {"token_info": {}}
        )
    except Exception as e:
        logger.error("Failed to query %s token_info: %s", symbol, e)
        raise HTTPException(status_code=502, detail=f"Failed to query {symbol} supply")

    raw_supply = int(result["token_info"]["total_supply"])
    supply = raw_supply / (10 ** token["decimals"])
    return _format_decimal(supply)


@router.get("/supply/erth", summary="ERTH Total Supply", response_class=PlainTextResponse)
async def get_erth_supply(
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client),
):
    """Returns the current ERTH total supply as a plain number with decimals."""
    return await _get_token_supply("ERTH", secret_async_client)


@router.get("/supply/anml", summary="ANML Total Supply", response_class=PlainTextResponse)
async def get_anml_supply(
    secret_async_client: AsyncLCDClient = Depends(get_async_secret_client),
):
    """Returns the current ANML total supply as a plain number with decimals."""
    return await _get_token_supply("ANML", secret_async_client)
