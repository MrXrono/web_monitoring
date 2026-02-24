"""Background task scheduler for RAID Monitor."""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.server import Server
from app.models.smart_history import SmartHistory
from app.models.event import ControllerEvent
from app.models.alert import AlertHistory
from app.models.setting import Setting

logger = logging.getLogger(__name__)


async def cleanup_old_data():
    """Delete old SMART history, events, and resolved alerts based on retention settings."""
    try:
        async with async_session() as db:
            # Get retention days from settings
            result = await db.execute(
                select(Setting).where(Setting.key == "general.retention_days")
            )
            setting = result.scalar_one_or_none()
            retention_days = int(setting.value) if setting and setting.value else 90

            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

            # Delete old SMART history
            from sqlalchemy import delete
            result = await db.execute(
                delete(SmartHistory).where(SmartHistory.recorded_at < cutoff)
            )
            smart_deleted = result.rowcount

            # Delete old events
            result = await db.execute(
                delete(ControllerEvent).where(ControllerEvent.created_at < cutoff)
            )
            events_deleted = result.rowcount

            # Delete old resolved alerts (keep 365 days)
            alert_cutoff = datetime.now(timezone.utc) - timedelta(days=365)
            result = await db.execute(
                delete(AlertHistory).where(
                    and_(AlertHistory.is_resolved == True, AlertHistory.created_at < alert_cutoff)
                )
            )
            alerts_deleted = result.rowcount

            await db.commit()

            if smart_deleted or events_deleted or alerts_deleted:
                logger.info(
                    f"Data cleanup: deleted {smart_deleted} SMART records, "
                    f"{events_deleted} events, {alerts_deleted} resolved alerts"
                )
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
