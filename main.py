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
from routers import chat, analytics, verify, airdrop, secret_query, faucet, app_version
# Import scheduled tasks
from scheduled_tasks import (
    update_pool_rewards,
    update_analytics_job,
    init_analytics,
    scheduled_weekly_job
)

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
    print("=" * 80, flush=True)
    print("APPLICATION STARTUP BEGINNING", flush=True)
    print("=" * 80, flush=True)

    # Load contract registry from on-chain
    print("Loading contract registry from on-chain...", flush=True)
    try:
        registry_data = load_registry(config.SECRET_LCD_URL, config.SECRET_CHAIN_ID)
        print(f"Registry data loaded: {len(registry_data.contracts)} contracts, {len(registry_data.tokens)} tokens", flush=True)
        print(f"Contract names: {list(registry_data.contracts.keys())}", flush=True)
        print(f"Token symbols: {list(registry_data.tokens.keys())}", flush=True)
        config.init_contracts_from_registry(registry_data.contracts, registry_data.tokens)
        print("Contract registry loaded successfully!", flush=True)
    except Exception as e:
        print(f"FATAL: Failed to load contract registry: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        raise

    # Initialize analytics data
    print("Initializing analytics...", flush=True)
    init_analytics()
    # Schedule analytics update to run every hour
    scheduler.add_job(update_analytics_job, 'interval', hours=1)
    # Schedule weekly Merkle generation every Sunday at 00:00 UTC
    scheduler.add_job(scheduled_weekly_job, 'cron', day_of_week='sun', hour=0, minute=0, timezone=timezone.utc)
    # Schedule daily pool rewards update at 00:00 UTC
    scheduler.add_job(update_pool_rewards, 'cron', hour=0, minute=0, timezone=timezone.utc)

    # Optionally run Merkle job once on startup when enabled via env
    if getattr(config, "MERKLE_RUN_ON_STARTUP", False):
        try:
            validator = getattr(config, "MERKLE_VALIDATOR", "").strip()
            if validator:
                print("MERKLE_RUN_ON_STARTUP enabled: running Merkle job and submitting to contract at startup...")
                scheduled_weekly_job()
            else:
                print("MERKLE_RUN_ON_STARTUP set but MERKLE_VALIDATOR is not configured; skipping.")
        except Exception as e:
            print(f"[AIRDROP] Startup Merkle job failed: {e}")

    scheduler.start()
    print("Startup complete. Analytics and airdrop schedulers are running.")

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
app.include_router(app_version.router, tags=["App Version"])


@app.get("/", tags=["Health Check"])
async def read_root():
    return {"message": "Welcome to the Erth Network API"}

# --- Run Server ---
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.WEBHOOK_PORT,
        reload=True
    )