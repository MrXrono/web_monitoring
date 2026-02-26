import logging
import math
import uuid
from datetime import datetime
from app.config import MSK

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.alert import AlertRule, AlertHistory
from app.models.server import Server
from app.schemas.alert import (
    AlertRuleResponse,
    AlertRuleUpdateRequest,
    AlertRuleListResponse,
    AlertHistoryItem,
    AlertHistoryListResponse,
    AlertSummaryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID: {value}",
        )


@router.get("/rules", response_model=AlertRuleListResponse)
async def list_rules(
    category: str | None = Query(None, description="Filter by category"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all alert rules, optionally filtered by category."""
    query = select(AlertRule)

    if category:
        query = query.where(AlertRule.category == category)

    query = query.order_by(AlertRule.category.asc(), AlertRule.name.asc())

    result = await db.execute(query)
    rules = result.scalars().all()

    return AlertRuleListResponse(
        items=[
            AlertRuleResponse(
                id=str(r.id),
                name=r.name,
                name_ru=r.name_ru,
                description=r.description,
                description_ru=r.description_ru,
                category=r.category,
                condition_type=r.condition_type,
                condition_params=r.condition_params,
                severity=r.severity,
                is_enabled=r.is_enabled,
                is_builtin=r.is_builtin,
                notify_telegram=r.notify_telegram,
                cooldown_minutes=r.cooldown_minutes,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in rules
        ],
        total=len(rules),
    )


@router.put("/rules/{rule_id}", response_model=AlertRuleResponse)
async def update_rule(
    rule_id: str,
    payload: AlertRuleUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an alert rule (enable/disable, change severity, etc.)."""
    rid = _parse_uuid(rule_id)

    result = await db.execute(select(AlertRule).where(AlertRule.id == rid))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert rule not found",
        )

    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled
    if payload.severity is not None:
        if payload.severity not in ("info", "warning", "critical"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Severity must be one of: info, warning, critical",
            )
        rule.severity = payload.severity
    if payload.notify_telegram is not None:
        rule.notify_telegram = payload.notify_telegram
    if payload.cooldown_minutes is not None:
        if payload.cooldown_minutes < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cooldown minutes must be >= 0",
            )
        rule.cooldown_minutes = payload.cooldown_minutes
    if payload.condition_params is not None:
        rule.condition_params = payload.condition_params

    await db.commit()
    await db.refresh(rule)

    return AlertRuleResponse(
        id=str(rule.id),
        name=rule.name,
        name_ru=rule.name_ru,
        description=rule.description,
        description_ru=rule.description_ru,
        category=rule.category,
        condition_type=rule.condition_type,
        condition_params=rule.condition_params,
        severity=rule.severity,
        is_enabled=rule.is_enabled,
        is_builtin=rule.is_builtin,
        notify_telegram=rule.notify_telegram,
        cooldown_minutes=rule.cooldown_minutes,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.get("/history", response_model=AlertHistoryListResponse)
async def list_alert_history(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    server_id: str | None = Query(None),
    is_resolved: bool | None = Query(None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List alert history with pagination and filtering."""
    query = select(AlertHistory).outerjoin(Server, AlertHistory.server_id == Server.id)

    filters = []
    if severity:
        filters.append(AlertHistory.severity == severity)
    if server_id:
        sid = _parse_uuid(server_id)
        filters.append(AlertHistory.server_id == sid)
    if is_resolved is not None:
        filters.append(AlertHistory.is_resolved == is_resolved)

    if filters:
        query = query.where(and_(*filters))

    # Count total
    count_query = select(func.count()).select_from(
        select(AlertHistory.id).outerjoin(Server, AlertHistory.server_id == Server.id)
        .where(and_(*filters) if filters else True)
        .subquery()
    )
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate, newest first
    query = query.order_by(AlertHistory.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    # We need the server hostname, so join and add columns
    result = await db.execute(
        select(AlertHistory, Server.hostname)
        .outerjoin(Server, AlertHistory.server_id == Server.id)
        .where(and_(*filters) if filters else True)
        .order_by(AlertHistory.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    rows = result.all()

    pages = math.ceil(total / per_page) if total > 0 else 1

    items = []
    for alert, hostname in rows:
        items.append(AlertHistoryItem(
            id=alert.id,
            rule_id=str(alert.rule_id) if alert.rule_id else None,
            server_id=str(alert.server_id) if alert.server_id else None,
            server_hostname=hostname,
            severity=alert.severity,
            title=alert.title,
            message=alert.message,
            context=alert.context,
            is_resolved=alert.is_resolved,
            resolved_at=alert.resolved_at,
            notified_telegram=alert.notified_telegram,
            created_at=alert.created_at,
        ))

    return AlertHistoryListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.post("/history/{alert_id}/resolve", status_code=status.HTTP_200_OK)
async def resolve_alert(
    alert_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resolve (acknowledge) an alert."""
    result = await db.execute(
        select(AlertHistory).where(AlertHistory.id == alert_id)
    )
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    if alert.is_resolved:
        return {"status": "ok", "message": "Alert already resolved"}

    alert.is_resolved = True
    alert.resolved_at = datetime.now(MSK)
    await db.commit()

    return {"status": "ok", "message": "Alert resolved"}


@router.get("/summary", response_model=AlertSummaryResponse)
async def alert_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert counts by severity and resolution status."""
    # Total count
    total_result = await db.execute(select(func.count(AlertHistory.id)))
    total = total_result.scalar() or 0

    # Active (unresolved) count
    active_result = await db.execute(
        select(func.count(AlertHistory.id)).where(AlertHistory.is_resolved.is_(False))
    )
    active = active_result.scalar() or 0

    resolved = total - active

    # Counts by severity (active only)
    severity_result = await db.execute(
        select(
            AlertHistory.severity,
            func.count(AlertHistory.id),
        )
        .where(AlertHistory.is_resolved.is_(False))
        .group_by(AlertHistory.severity)
    )
    severity_counts = {row[0]: row[1] for row in severity_result.all()}

    return AlertSummaryResponse(
        total=total,
        active=active,
        resolved=resolved,
        critical=severity_counts.get("critical", 0),
        warning=severity_counts.get("warning", 0),
        info=severity_counts.get("info", 0),
    )
