import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.server import Server
from app.models.controller import Controller
from app.models.virtual_drive import VirtualDrive
from app.models.physical_drive import PhysicalDrive
from app.models.alert import AlertHistory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
async def dashboard_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get summary statistics for the dashboard:
    server, controller, VD, PD counts by status, and active alert counts.
    """
    # Server counts by status
    server_result = await db.execute(
        select(Server.status, func.count(Server.id)).group_by(Server.status)
    )
    server_counts = dict(server_result.all())
    total_servers = sum(server_counts.values())

    # Controller counts by status
    ctrl_result = await db.execute(
        select(Controller.status, func.count(Controller.id)).group_by(Controller.status)
    )
    ctrl_counts = dict(ctrl_result.all())
    total_controllers = sum(ctrl_counts.values())

    # Virtual Drive counts by state
    vd_result = await db.execute(
        select(VirtualDrive.state, func.count(VirtualDrive.id)).group_by(VirtualDrive.state)
    )
    vd_counts = dict(vd_result.all())
    total_vds = sum(vd_counts.values())

    # Physical Drive counts by state
    pd_result = await db.execute(
        select(PhysicalDrive.state, func.count(PhysicalDrive.id)).group_by(PhysicalDrive.state)
    )
    pd_counts = dict(pd_result.all())
    total_pds = sum(pd_counts.values())

    # PDs with SMART alerts
    smart_alert_result = await db.execute(
        select(func.count(PhysicalDrive.id)).where(PhysicalDrive.smart_alert.is_(True))
    )
    smart_alert_count = smart_alert_result.scalar() or 0

    # Active alerts count by severity
    alert_result = await db.execute(
        select(AlertHistory.severity, func.count(AlertHistory.id))
        .where(AlertHistory.is_resolved.is_(False))
        .group_by(AlertHistory.severity)
    )
    alert_counts = dict(alert_result.all())
    total_active_alerts = sum(alert_counts.values())

    return {
        "servers": {
            "total": total_servers,
            "by_status": server_counts,
        },
        "controllers": {
            "total": total_controllers,
            "by_status": ctrl_counts,
        },
        "virtual_drives": {
            "total": total_vds,
            "by_state": vd_counts,
        },
        "physical_drives": {
            "total": total_pds,
            "by_state": pd_counts,
            "smart_alerts": smart_alert_count,
        },
        "alerts": {
            "active_total": total_active_alerts,
            "by_severity": alert_counts,
        },
    }


@router.get("/health")
async def dashboard_health(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get health overview for all servers.
    Returns each server with a computed health status based on its components.
    """
    now = datetime.now(timezone.utc)
    offline_threshold = now - timedelta(minutes=15)

    result = await db.execute(
        select(Server).order_by(Server.hostname.asc())
    )
    servers = result.scalars().all()

    health_list = []

    for srv in servers:
        # Determine health
        issues = []

        # Check if agent is reporting
        if srv.last_seen and srv.last_seen < offline_threshold:
            issues.append("Agent offline (no report in >15 min)")

        if srv.status == "unknown":
            issues.append("Status unknown")

        # Count degraded VDs
        vd_result = await db.execute(
            select(VirtualDrive.state, func.count(VirtualDrive.id))
            .join(Controller, VirtualDrive.controller_id == Controller.id)
            .where(Controller.server_id == srv.id)
            .group_by(VirtualDrive.state)
        )
        vd_states = dict(vd_result.all())

        degraded_vds = 0
        for state, count in vd_states.items():
            if state and state.lower() not in ("optimal", "optl"):
                degraded_vds += count
                issues.append(f"{count} VD(s) in state '{state}'")

        # Count drives with errors
        pd_error_result = await db.execute(
            select(func.count(PhysicalDrive.id))
            .join(Controller, PhysicalDrive.controller_id == Controller.id)
            .where(
                Controller.server_id == srv.id,
                (PhysicalDrive.media_error_count > 0)
                | (PhysicalDrive.predictive_failure > 0)
                | (PhysicalDrive.smart_alert.is_(True))
            )
        )
        pd_errors = pd_error_result.scalar() or 0
        if pd_errors:
            issues.append(f"{pd_errors} PD(s) with errors/alerts")

        # Count offline/failed PDs
        pd_bad_result = await db.execute(
            select(func.count(PhysicalDrive.id))
            .join(Controller, PhysicalDrive.controller_id == Controller.id)
            .where(
                Controller.server_id == srv.id,
                PhysicalDrive.state.notin_(["Online", "Onln", "JBOD", "GHS", "DHS", "UGood"]),
            )
        )
        pd_bad = pd_bad_result.scalar() or 0
        if pd_bad:
            issues.append(f"{pd_bad} PD(s) not Online")

        # Active alerts for this server
        alert_result = await db.execute(
            select(func.count(AlertHistory.id))
            .where(AlertHistory.server_id == srv.id, AlertHistory.is_resolved.is_(False))
        )
        active_alerts = alert_result.scalar() or 0

        # Compute overall health
        if degraded_vds > 0 or pd_bad > 0:
            health = "critical"
        elif pd_errors > 0 or active_alerts > 0:
            health = "warning"
        elif srv.last_seen and srv.last_seen < offline_threshold:
            health = "offline"
        elif srv.status == "online":
            health = "healthy"
        else:
            health = "unknown"

        health_list.append({
            "id": str(srv.id),
            "hostname": srv.hostname,
            "ip_address": srv.ip_address,
            "status": srv.status,
            "health": health,
            "last_seen": srv.last_seen.isoformat() if srv.last_seen else None,
            "active_alerts": active_alerts,
            "issues": issues,
        })

    return {"servers": health_list}
