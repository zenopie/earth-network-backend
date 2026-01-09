# /routers/analytics.py
"""
Analytics API endpoints for ERTH Network.
The scheduled analytics update job is in scheduled_tasks/analytics.py
"""
from fastapi import APIRouter

# Import scheduled task functions
from scheduled_tasks.analytics import init_analytics, get_analytics_history, get_latest_data_point

router = APIRouter()

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