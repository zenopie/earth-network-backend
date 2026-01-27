# /main.py
import uvicorn
import os
import logging
from datetime import timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import config
from registry_loader import load_registry

logger = logging.getLogger(__name__)
# Import the individual router modules
from routers import chat, analytics, verify, airdrop, secret_query, faucet, monero_bridge
# Import scheduled tasks
from scheduled_tasks import (
    update_pool_rewards,
    update_analytics_job,
    init_analytics,
    scheduled_weekly_job
)
from scheduled_tasks.monero_bridge import init_monero_bridge, poll_deposits

app = FastAPI(
    title="Erth Network API",
    description="Backend services for Erth Network applications.",
    version="1.4.0" # Version bump to reflect change
)

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# --- Event Handlers & Scheduler ---
scheduler = AsyncIOScheduler()

@app.on_event("startup")
async def startup_event():
    """Initializes analytics and starts the scheduler."""
    import sys
    print("\n[Startup] ERTH Network Backend starting...", flush=True)

    # Load contract registry from on-chain
    try:
        registry_data = load_registry(config.SECRET_LCD_URL, config.SECRET_CHAIN_ID)
        config.init_contracts_from_registry(registry_data.contracts, registry_data.tokens)
        print(f"[Startup] Registry: {len(registry_data.contracts)} contracts, {len(registry_data.tokens)} tokens", flush=True)
    except Exception as e:
        print(f"[Startup] FATAL: Registry load failed: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        raise

    # Initialize analytics
    await init_analytics()
    scheduler.add_job(update_analytics_job, 'interval', hours=1, id='analytics_update')

    # Schedule other jobs
    scheduler.add_job(scheduled_weekly_job, 'cron', day_of_week='sun', hour=0, minute=0, timezone=timezone.utc, id='weekly_merkle')
    scheduler.add_job(update_pool_rewards, 'cron', hour=23, minute=0, timezone=timezone.utc, id='daily_pool_rewards')

    # Initialize Monero bridge
    await init_monero_bridge()
    if config.MONERO_BRIDGE_ENABLED:
        scheduler.add_job(poll_deposits, 'interval', seconds=30, id='monero_deposit_poll')

    # Optionally run Merkle job once on startup
    if getattr(config, "MERKLE_RUN_ON_STARTUP", False):
        try:
            validator = getattr(config, "MERKLE_VALIDATOR", "").strip()
            if validator:
                print("[Startup] Running Merkle job...", flush=True)
                scheduled_weekly_job()
        except Exception as e:
            print(f"[Startup] Merkle failed: {e}", flush=True)

    scheduler.start()
    print("[Startup] Ready\n", flush=True)

@app.on_event("shutdown")
def shutdown_event():
    """Shuts down the scheduler."""
    scheduler.shutdown()
    print("Application shutdown.")

# --- API Routers ---
app.include_router(chat.router, tags=["Chat"])
app.include_router(analytics.router, tags=["Analytics"])
app.include_router(verify.router, tags=["Verification"])
app.include_router(airdrop.router, tags=["Airdrop"])
app.include_router(secret_query.router, tags=["SecretQuery"])
app.include_router(faucet.router, tags=["Faucet"])
app.include_router(monero_bridge.router, tags=["Monero Bridge"])


@app.get("/", tags=["Health Check"])
async def read_root():
    return {"message": "Welcome to the Erth Network API"}

# --- Run Server ---
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.WEBHOOK_PORT,
        reload=True,
        access_log=False
    )