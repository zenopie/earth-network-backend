# /routers/app_version.py

import os
from fastapi import APIRouter

router = APIRouter()

@router.get("/app/version")
async def get_app_version():
    """Get app version information for update management."""
    return {
        "current_version": os.getenv("APP_CURRENT_VERSION", "1.0.0"),
        "minimum_version": os.getenv("APP_MINIMUM_VERSION", "1.0.0"),
        "update_message": os.getenv("APP_UPDATE_MESSAGE", "First Release"),
        "download_url": os.getenv("APP_DOWNLOAD_URL", "https://play.google.com/store/apps/details?id=com.example.earthwallet")
    }