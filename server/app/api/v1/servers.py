import logging
import math
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.server import Server
from app.models.controller import Controller
from app.models.bbu import BbuUnit
from app.models.virtual_drive import VirtualDrive
from app.models.physical_drive import PhysicalDrive
from app.models.smart_history import SmartHistory
from app.models.event import ControllerEvent
from app.schemas.server import (
    ServerListItem,
    ServerListResponse,
    ServerDetailResponse,
    ControllerResponse,
    ControllerDetailResponse,
    BbuResponse,
    VirtualDriveResponse,
    PhysicalDriveResponse,
    EventResponse,
    EventListResponse,
    SmartHistoryEntry,
    SmartHistoryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["servers"])


def _parse_uuid(value: str) -> uuid.UUID:
    """Parse a string as UUID, raising 400 on failure."""
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID: {value}",
        )


@router.get("/", response_model=ServerListResponse)
async def list_servers(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    search: str | None = Query(None, description="Search by hostname or IP"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all servers with pagination and optional filters."""
    query = select(Server)

    if search:
        pattern = f"%{search}%"
        query = query.where(
            Server.hostname.ilike(pattern) | Server.ip_address.ilike(pattern)
        )

    if status_filter:
        query = query.where(Server.status == status_filter)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    query = query.order_by(Server.hostname.asc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query.options(selectinload(Server.controllers)))
    servers = result.scalars().unique().all()

    items = []
    for srv in servers:
        # Count VDs and PDs across all controllers
        vd_count = 0
        pd_count = 0
        for ctrl in srv.controllers:
            # Lazy-load counts via separate queries for accuracy
            pass  # We'll use the relationship length below

        # For efficiency in list view, count via subqueries
        ctrl_ids = [c.id for c in srv.controllers]
        if ctrl_ids:
            vd_result = await db.execute(
                select(func.count()).where(VirtualDrive.controller_id.in_(ctrl_ids))
            )
            vd_count = vd_result.scalar() or 0

            pd_result = await db.execute(
                select(func.count()).where(PhysicalDrive.controller_id.in_(ctrl_ids))
            )
            pd_count = pd_result.scalar() or 0

        items.append(ServerListItem(
            id=str(srv.id),
            hostname=srv.hostname,
            fqdn=srv.fqdn,
            ip_address=srv.ip_address,
            os_name=srv.os_name,
            os_version=srv.os_version,
            agent_version=srv.agent_version,
            status=srv.status,
            debug_mode=srv.debug_mode,
            last_seen=srv.last_seen,
            controller_count=len(srv.controllers),
            vd_count=vd_count,
            pd_count=pd_count,
            created_at=srv.created_at,
        ))

    pages = math.ceil(total / per_page) if total > 0 else 1

    return ServerListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get("/{server_id}", response_model=ServerDetailResponse)
async def get_server(
    server_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed information about a server including its controllers."""
    sid = _parse_uuid(server_id)

    result = await db.execute(
        select(Server)
        .where(Server.id == sid)
        .options(
            selectinload(Server.controllers)
            .selectinload(Controller.bbu),
            selectinload(Server.controllers)
            .selectinload(Controller.virtual_drives),
            selectinload(Server.controllers)
            .selectinload(Controller.physical_drives),
        )
    )
    server = result.scalar_one_or_none()

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    controllers = []
    for ctrl in server.controllers:
        bbu_resp = None
        if ctrl.bbu:
            bbu_resp = BbuResponse(
                id=str(ctrl.bbu.id),
                bbu_type=ctrl.bbu.bbu_type,
                state=ctrl.bbu.state,
                voltage=ctrl.bbu.voltage,
                temperature=ctrl.bbu.temperature,
                learn_cycle_status=ctrl.bbu.learn_cycle_status,
                replacement_needed=ctrl.bbu.replacement_needed,
            )

        vds = [
            VirtualDriveResponse(
                id=str(vd.id),
                vd_id=vd.vd_id,
                dg_id=vd.dg_id,
                name=vd.name,
                raid_type=vd.raid_type,
                state=vd.state,
                size=vd.size,
                strip_size=vd.strip_size,
                number_of_drives=vd.number_of_drives,
                cache_policy=vd.cache_policy,
                io_policy=vd.io_policy,
                read_policy=vd.read_policy,
                disk_cache_policy=vd.disk_cache_policy,
                consistent=vd.consistent,
                access=vd.access,
                created_at=vd.created_at,
                updated_at=vd.updated_at,
            )
            for vd in ctrl.virtual_drives
        ]

        pds = [
            PhysicalDriveResponse(
                id=str(pd.id),
                enclosure_id=pd.enclosure_id,
                slot_number=pd.slot_number,
                device_id=pd.device_id,
                drive_group=pd.drive_group,
                state=pd.state,
                size=pd.size,
                media_type=pd.media_type,
                interface_type=pd.interface_type,
                model=pd.model,
                serial_number=pd.serial_number,
                firmware_version=pd.firmware_version,
                manufacturer=pd.manufacturer,
                temperature=pd.temperature,
                media_error_count=pd.media_error_count,
                other_error_count=pd.other_error_count,
                predictive_failure=pd.predictive_failure,
                smart_alert=pd.smart_alert,
                created_at=pd.created_at,
                updated_at=pd.updated_at,
            )
            for pd in ctrl.physical_drives
        ]

        controllers.append(ControllerDetailResponse(
            id=str(ctrl.id),
            controller_id=ctrl.controller_id,
            model=ctrl.model,
            serial_number=ctrl.serial_number,
            firmware_version=ctrl.firmware_version,
            bios_version=ctrl.bios_version,
            driver_version=ctrl.driver_version,
            status=ctrl.status,
            memory_size=ctrl.memory_size,
            memory_correctable_errors=ctrl.memory_correctable_errors,
            memory_uncorrectable_errors=ctrl.memory_uncorrectable_errors,
            roc_temperature=ctrl.roc_temperature,
            rebuild_rate=ctrl.rebuild_rate,
            patrol_read_status=ctrl.patrol_read_status,
            cc_status=ctrl.cc_status,
            alarm_status=ctrl.alarm_status,
            created_at=ctrl.created_at,
            updated_at=ctrl.updated_at,
            bbu=bbu_resp,
            virtual_drives=vds,
            physical_drives=pds,
        ))

    return ServerDetailResponse(
        id=str(server.id),
        hostname=server.hostname,
        fqdn=server.fqdn,
        ip_address=server.ip_address,
        os_name=server.os_name,
        os_version=server.os_version,
        kernel_version=server.kernel_version,
        agent_version=server.agent_version,
        storcli_version=server.storcli_version,
        cpu_model=server.cpu_model,
        cpu_cores=server.cpu_cores,
        ram_total_gb=server.ram_total_gb,
        uptime_seconds=server.uptime_seconds,
        last_os_update=server.last_os_update,
        status=server.status,
        debug_mode=server.debug_mode,
        notes=server.notes,
        last_seen=server.last_seen,
        created_at=server.created_at,
        updated_at=server.updated_at,
        controllers=controllers,
    )


@router.delete("/{server_id}", status_code=status.HTTP_200_OK)
async def delete_server(
    server_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a server and all its related data (cascading)."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    sid = _parse_uuid(server_id)

    result = await db.execute(select(Server).where(Server.id == sid))
    server = result.scalar_one_or_none()

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    hostname = server.hostname
    await db.delete(server)
    await db.commit()

    return {"status": "ok", "message": f"Server '{hostname}' deleted"}


@router.post("/{server_id}/debug", status_code=status.HTTP_200_OK)
async def toggle_debug(
    server_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle debug mode for a server's agent."""
    sid = _parse_uuid(server_id)

    result = await db.execute(select(Server).where(Server.id == sid))
    server = result.scalar_one_or_none()

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    server.debug_mode = not server.debug_mode
    await db.commit()

    return {
        "status": "ok",
        "debug_mode": server.debug_mode,
        "message": f"Debug mode {'enabled' if server.debug_mode else 'disabled'} for {server.hostname}",
    }


@router.post("/{server_id}/collect-logs", status_code=status.HTTP_200_OK)
async def collect_logs(
    server_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Request the agent to upload its logs on the next check-in."""
    sid = _parse_uuid(server_id)

    result = await db.execute(select(Server).where(Server.id == sid))
    server = result.scalar_one_or_none()

    if server is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found",
        )

    # Add a command to the server's pending commands
    import secrets
    cmd_id = secrets.token_hex(8)
    command = {
        "id": cmd_id,
        "type": "collect_logs",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    server_info = server.server_info or {}
    pending = server_info.get("pending_commands", [])
    pending.append(command)
    server_info["pending_commands"] = pending
    server.server_info = server_info
    await db.commit()

    return {"status": "ok", "command_id": cmd_id, "message": f"Log collection requested for {server.hostname}"}


@router.get("/{server_id}/controllers", response_model=list[ControllerResponse])
async def list_controllers(
    server_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all controllers for a server."""
    sid = _parse_uuid(server_id)

    result = await db.execute(
        select(Controller)
        .where(Controller.server_id == sid)
        .order_by(Controller.controller_id.asc())
    )
    controllers = result.scalars().all()

    return [
        ControllerResponse(
            id=str(ctrl.id),
            controller_id=ctrl.controller_id,
            model=ctrl.model,
            serial_number=ctrl.serial_number,
            firmware_version=ctrl.firmware_version,
            bios_version=ctrl.bios_version,
            driver_version=ctrl.driver_version,
            status=ctrl.status,
            memory_size=ctrl.memory_size,
            memory_correctable_errors=ctrl.memory_correctable_errors,
            memory_uncorrectable_errors=ctrl.memory_uncorrectable_errors,
            roc_temperature=ctrl.roc_temperature,
            rebuild_rate=ctrl.rebuild_rate,
            patrol_read_status=ctrl.patrol_read_status,
            cc_status=ctrl.cc_status,
            alarm_status=ctrl.alarm_status,
            created_at=ctrl.created_at,
            updated_at=ctrl.updated_at,
        )
        for ctrl in controllers
    ]


@router.get("/{server_id}/controllers/{ctrl_id}", response_model=ControllerDetailResponse)
async def get_controller(
    server_id: str,
    ctrl_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed controller info including BBU, VDs, and PDs."""
    sid = _parse_uuid(server_id)
    cid = _parse_uuid(ctrl_id)

    result = await db.execute(
        select(Controller)
        .where(Controller.id == cid, Controller.server_id == sid)
        .options(
            selectinload(Controller.bbu),
            selectinload(Controller.virtual_drives),
            selectinload(Controller.physical_drives),
        )
    )
    ctrl = result.scalar_one_or_none()

    if ctrl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    bbu_resp = None
    if ctrl.bbu:
        bbu_resp = BbuResponse(
            id=str(ctrl.bbu.id),
            bbu_type=ctrl.bbu.bbu_type,
            state=ctrl.bbu.state,
            voltage=ctrl.bbu.voltage,
            temperature=ctrl.bbu.temperature,
            learn_cycle_status=ctrl.bbu.learn_cycle_status,
            replacement_needed=ctrl.bbu.replacement_needed,
        )

    vds = [
        VirtualDriveResponse(
            id=str(vd.id),
            vd_id=vd.vd_id,
            dg_id=vd.dg_id,
            name=vd.name,
            raid_type=vd.raid_type,
            state=vd.state,
            size=vd.size,
            strip_size=vd.strip_size,
            number_of_drives=vd.number_of_drives,
            cache_policy=vd.cache_policy,
            io_policy=vd.io_policy,
            read_policy=vd.read_policy,
            disk_cache_policy=vd.disk_cache_policy,
            consistent=vd.consistent,
            access=vd.access,
            created_at=vd.created_at,
            updated_at=vd.updated_at,
        )
        for vd in ctrl.virtual_drives
    ]

    pds = [
        PhysicalDriveResponse(
            id=str(pd.id),
            enclosure_id=pd.enclosure_id,
            slot_number=pd.slot_number,
            device_id=pd.device_id,
            drive_group=pd.drive_group,
            state=pd.state,
            size=pd.size,
            media_type=pd.media_type,
            interface_type=pd.interface_type,
            model=pd.model,
            serial_number=pd.serial_number,
            firmware_version=pd.firmware_version,
            manufacturer=pd.manufacturer,
            temperature=pd.temperature,
            media_error_count=pd.media_error_count,
            other_error_count=pd.other_error_count,
            predictive_failure=pd.predictive_failure,
            smart_alert=pd.smart_alert,
            created_at=pd.created_at,
            updated_at=pd.updated_at,
        )
        for pd in ctrl.physical_drives
    ]

    return ControllerDetailResponse(
        id=str(ctrl.id),
        controller_id=ctrl.controller_id,
        model=ctrl.model,
        serial_number=ctrl.serial_number,
        firmware_version=ctrl.firmware_version,
        bios_version=ctrl.bios_version,
        driver_version=ctrl.driver_version,
        status=ctrl.status,
        memory_size=ctrl.memory_size,
        memory_correctable_errors=ctrl.memory_correctable_errors,
        memory_uncorrectable_errors=ctrl.memory_uncorrectable_errors,
        roc_temperature=ctrl.roc_temperature,
        rebuild_rate=ctrl.rebuild_rate,
        patrol_read_status=ctrl.patrol_read_status,
        cc_status=ctrl.cc_status,
        alarm_status=ctrl.alarm_status,
        created_at=ctrl.created_at,
        updated_at=ctrl.updated_at,
        bbu=bbu_resp,
        virtual_drives=vds,
        physical_drives=pds,
    )


@router.get("/{server_id}/controllers/{ctrl_id}/vds", response_model=list[VirtualDriveResponse])
async def list_virtual_drives(
    server_id: str,
    ctrl_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List virtual drives for a controller."""
    sid = _parse_uuid(server_id)
    cid = _parse_uuid(ctrl_id)

    # Verify controller belongs to server
    result = await db.execute(
        select(Controller).where(Controller.id == cid, Controller.server_id == sid)
    )
    ctrl = result.scalar_one_or_none()
    if ctrl is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controller not found")

    result = await db.execute(
        select(VirtualDrive)
        .where(VirtualDrive.controller_id == cid)
        .order_by(VirtualDrive.vd_id.asc())
    )
    vds = result.scalars().all()

    return [
        VirtualDriveResponse(
            id=str(vd.id),
            vd_id=vd.vd_id,
            dg_id=vd.dg_id,
            name=vd.name,
            raid_type=vd.raid_type,
            state=vd.state,
            size=vd.size,
            strip_size=vd.strip_size,
            number_of_drives=vd.number_of_drives,
            cache_policy=vd.cache_policy,
            io_policy=vd.io_policy,
            read_policy=vd.read_policy,
            disk_cache_policy=vd.disk_cache_policy,
            consistent=vd.consistent,
            access=vd.access,
            created_at=vd.created_at,
            updated_at=vd.updated_at,
        )
        for vd in vds
    ]


@router.get("/{server_id}/controllers/{ctrl_id}/pds", response_model=list[PhysicalDriveResponse])
async def list_physical_drives(
    server_id: str,
    ctrl_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List physical drives for a controller."""
    sid = _parse_uuid(server_id)
    cid = _parse_uuid(ctrl_id)

    result = await db.execute(
        select(Controller).where(Controller.id == cid, Controller.server_id == sid)
    )
    ctrl = result.scalar_one_or_none()
    if ctrl is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controller not found")

    result = await db.execute(
        select(PhysicalDrive)
        .where(PhysicalDrive.controller_id == cid)
        .order_by(PhysicalDrive.enclosure_id.asc(), PhysicalDrive.slot_number.asc())
    )
    pds = result.scalars().all()

    return [
        PhysicalDriveResponse(
            id=str(pd.id),
            enclosure_id=pd.enclosure_id,
            slot_number=pd.slot_number,
            device_id=pd.device_id,
            drive_group=pd.drive_group,
            state=pd.state,
            size=pd.size,
            media_type=pd.media_type,
            interface_type=pd.interface_type,
            model=pd.model,
            serial_number=pd.serial_number,
            firmware_version=pd.firmware_version,
            manufacturer=pd.manufacturer,
            temperature=pd.temperature,
            media_error_count=pd.media_error_count,
            other_error_count=pd.other_error_count,
            predictive_failure=pd.predictive_failure,
            smart_alert=pd.smart_alert,
            created_at=pd.created_at,
            updated_at=pd.updated_at,
        )
        for pd in pds
    ]


@router.get("/{server_id}/controllers/{ctrl_id}/events", response_model=EventListResponse)
async def list_events(
    server_id: str,
    ctrl_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    severity: str | None = Query(None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List events for a controller with pagination."""
    sid = _parse_uuid(server_id)
    cid = _parse_uuid(ctrl_id)

    result = await db.execute(
        select(Controller).where(Controller.id == cid, Controller.server_id == sid)
    )
    ctrl = result.scalar_one_or_none()
    if ctrl is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controller not found")

    query = select(ControllerEvent).where(ControllerEvent.controller_id == cid)

    if severity:
        query = query.where(ControllerEvent.severity == severity)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate, newest first
    query = query.order_by(ControllerEvent.event_time.desc().nullslast(), ControllerEvent.id.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    events = result.scalars().all()

    pages = math.ceil(total / per_page) if total > 0 else 1

    return EventListResponse(
        items=[
            EventResponse(
                id=ev.id,
                event_id=ev.event_id,
                event_time=ev.event_time,
                severity=ev.severity,
                event_class=ev.event_class,
                event_description=ev.event_description,
                created_at=ev.created_at,
            )
            for ev in events
        ],
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get("/{server_id}/pds/{pd_id}/smart-history", response_model=SmartHistoryResponse)
async def get_smart_history(
    server_id: str,
    pd_id: str,
    limit: int = Query(100, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get SMART history for a physical drive."""
    sid = _parse_uuid(server_id)
    pdid = _parse_uuid(pd_id)

    # Verify the PD belongs to the server (through controller)
    result = await db.execute(
        select(PhysicalDrive)
        .join(Controller, PhysicalDrive.controller_id == Controller.id)
        .where(PhysicalDrive.id == pdid, Controller.server_id == sid)
    )
    pd_obj = result.scalar_one_or_none()
    if pd_obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Physical drive not found",
        )

    result = await db.execute(
        select(SmartHistory)
        .where(SmartHistory.physical_drive_id == pdid)
        .order_by(SmartHistory.recorded_at.desc())
        .limit(limit)
    )
    entries = result.scalars().all()

    # Get total count
    count_result = await db.execute(
        select(func.count()).where(SmartHistory.physical_drive_id == pdid)
    )
    total = count_result.scalar() or 0

    return SmartHistoryResponse(
        items=[
            SmartHistoryEntry(
                id=e.id,
                recorded_at=e.recorded_at,
                temperature=e.temperature,
                media_error_count=e.media_error_count,
                other_error_count=e.other_error_count,
                predictive_failure=e.predictive_failure,
                reallocated_sectors=e.reallocated_sectors,
                power_on_hours=e.power_on_hours,
                smart_data=e.smart_data,
            )
            for e in entries
        ],
        total=total,
    )
