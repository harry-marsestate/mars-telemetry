"""Dagster Definitions: wires the two InnoVint sync assets to a daily
schedule.

Daily, not hourly: per the InnoVint data inventory, 45/47 lots are
archived and only 3 vessels currently hold wine at all -- this is
overwhelmingly slow-changing/historical data, not a live feed. 6am
Pacific runs well outside any plausible winery business hours, minimizing
the chance of syncing mid-edit against InnoVint. Revisit if/when a
winery panel needs same-day fermentation lab readings for a currently
active lot -- daily would likely be insufficient then, but that's not
today's situation (see the InnoVint data inventory findings).
"""

from __future__ import annotations

from dagster import Definitions, ScheduleDefinition, define_asset_job

from .assets import analyses_sync, vessels_sync

innovint_sync_job = define_asset_job(
    name="innovint_sync_job",
    selection=[analyses_sync, vessels_sync],
)

innovint_sync_schedule = ScheduleDefinition(
    job=innovint_sync_job,
    cron_schedule="0 6 * * *",
    execution_timezone="America/Los_Angeles",
)

defs = Definitions(
    assets=[analyses_sync, vessels_sync],
    jobs=[innovint_sync_job],
    schedules=[innovint_sync_schedule],
)
