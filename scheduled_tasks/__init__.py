# /scheduled_tasks/__init__.py
"""
Scheduled tasks module for background jobs.
This module contains all scheduled tasks that run at specific intervals.
"""

from .pool_rewards import update_pool_rewards
from .analytics import update_analytics_job, init_analytics
from .airdrop import scheduled_weekly_job

__all__ = [
    'update_pool_rewards',
    'update_analytics_job',
    'init_analytics',
    'scheduled_weekly_job'
]
