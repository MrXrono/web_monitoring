"""
Core service for processing agent reports.

Receives structured reports from RAID monitoring agents, upserts all
hardware components (controllers, BBU, virtual drives, physical drives),
records SMART history and controller events, computes overall server
health status, and triggers alert evaluation.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Server,
    Controller,
    BbuUnit,
    VirtualDrive,
    PhysicalDrive,
    SmartHistory,
    ControllerEvent,
)
from app.services import alert_engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status computation helpers
# ---------------------------------------------------------------------------

# Priority order: higher index = worse status
_STATUS_PRIORITY = {
    "ok": 0,
    "optimal": 0,
    "online": 0,
    "info": 1,
    "warning": 2,
    "degraded": 3,
    "partially_degraded": 3,
    "rebuilding": 2,
    "critical": 4,
    "offline": 4,
    "failed": 4,
    "unknown": 1,
}


def _worst_status(*statuses: str) -> str:
    """Return the worst (highest priority) status from the given list."""
    worst = "ok"
    worst_p = 0
    for s in statuses:
        s_lower = s.lower() if s else "unknown"
        p = _STATUS_PRIORITY.get(s_lower, 1)
        if p > worst_p:
            worst_p = p
            worst = s_lower
    return worst


def _normalize_status(raw: str | None) -> str:
    """Normalize a raw component status string to a canonical form."""
    if not raw:
        return "unknown"
    s = raw.strip().lower().replace(" ", "_")
    return s


def _compute_server_status(
    controllers: list[dict],
    virtual_drives: list[dict],
    physical_drives: list[dict],
    bbu_data: list[dict],
) -> str:
    """
    Compute overall server health from component states.

    Rules:
    - critical: any VD degraded/offline, any PD failed
    - warning: any VD rebuilding, any PD rebuilding/copyback, BBU not optimal
    - ok: everything healthy
    """
    component_statuses = []

    for vd in virtual_drives:
        state = _normalize_status(vd.get("state"))
        if state in ("degraded", "partially_degraded", "offline"):
            component_statuses.append("critical")
        elif state in ("rebuilding", "rbld"):
            component_statuses.append("warning")
        elif state in ("optimal", "optl"):
            component_statuses.append("ok")
        else:
            component_statuses.append("warning")

    for pd in physical_drives:
        state = _normalize_status(pd.get("state"))
        if state in ("failed", "ubad", "ubunsp"):
            component_statuses.append("critical")
        elif state in ("rebuild", "rbld", "copyback"):
            component_statuses.append("warning")
        elif state in ("foreign", "frgn"):
            component_statuses.append("warning")
        elif state in ("online", "onln", "unconfigured_good", "ugood", "jbod", "ghs", "dhs"):
            component_statuses.append("ok")
        else:
            component_statuses.append("warning")

        if pd.get("predictive_failure", 0) > 0:
            component_statuses.append("warning")
        if pd.get("smart_alert"):
            component_statuses.append("warning")

    for ctrl in controllers:
        status = _normalize_status(ctrl.get("status"))
        if status not in ("ok", "optimal"):
            component_statuses.append("warning")
        roc_temp = ctrl.get("roc_temperature")
        if roc_temp is not None and isinstance(roc_temp, (int, float)):
            if roc_temp > 95:
                component_statuses.append("critical")
            elif roc_temp > 80:
                component_statuses.append("warning")
        mem_unc = ctrl.get("memory_uncorrectable_errors", 0) or 0
        if mem_unc > 0:
            component_statuses.append("warning")

    for bbu in bbu_data:
        state = _normalize_status(bbu.get("state"))
        if state not in ("ok", "optimal", "ready"):
            component_statuses.append("warning")
        if bbu.get("replacement_needed"):
            component_statuses.append("warning")
        temp = bbu.get("temperature")
        if temp is not None and isinstance(temp, (int, float)) and temp > 50:
            component_statuses.append("warning")

    if not component_statuses:
        return "unknown"

    return _worst_status(*component_statuses)


# ---------------------------------------------------------------------------
# Upsert helpers
# ---------------------------------------------------------------------------

async def _upsert_controller(
    db: AsyncSession,
    server_id: uuid.UUID,
    ctrl_data: dict,
) -> Controller:
    """Upsert a controller record for the given server."""
    controller_id = int(ctrl_data.get("controller_id", 0))

    result = await db.execute(
        select(Controller).where(
            and_(
                Controller.server_id == server_id,
                Controller.controller_id == controller_id,
            )
        )
    )
    ctrl = result.scalar_one_or_none()

    if ctrl is None:
        ctrl = Controller(
            server_id=server_id,
            controller_id=controller_id,
        )
        db.add(ctrl)

    ctrl.model = ctrl_data.get("model")
    ctrl.serial_number = ctrl_data.get("serial_number")
    ctrl.firmware_version = ctrl_data.get("firmware_version")
    ctrl.bios_version = ctrl_data.get("bios_version")
    ctrl.driver_version = ctrl_data.get("driver_version")
    ctrl.status = ctrl_data.get("status")
    ctrl.memory_size = ctrl_data.get("memory_size")
    ctrl.memory_correctable_errors = ctrl_data.get("memory_correctable_errors", 0) or 0
    ctrl.memory_uncorrectable_errors = ctrl_data.get("memory_uncorrectable_errors", 0) or 0
    ctrl.roc_temperature = ctrl_data.get("roc_temperature")
    ctrl.rebuild_rate = ctrl_data.get("rebuild_rate")
    ctrl.patrol_read_status = ctrl_data.get("patrol_read_status")
    ctrl.cc_status = ctrl_data.get("cc_status")
    ctrl.alarm_status = ctrl_data.get("alarm_status")
    ctrl.raw_data = ctrl_data.get("raw_data")

    await db.flush()
    return ctrl


async def _upsert_bbu(
    db: AsyncSession,
    controller_db_id: uuid.UUID,
    bbu_data: dict,
) -> BbuUnit | None:
    """Upsert a BBU record for the given controller."""
    if not bbu_data:
        return None

    result = await db.execute(
        select(BbuUnit).where(BbuUnit.controller_id == controller_db_id)
    )
    bbu = result.scalar_one_or_none()

    if bbu is None:
        bbu = BbuUnit(controller_id=controller_db_id)
        db.add(bbu)

    bbu.bbu_type = bbu_data.get("bbu_type") or bbu_data.get("type")
    bbu.state = bbu_data.get("state")
    bbu.voltage = bbu_data.get("voltage")
    bbu.temperature = bbu_data.get("temperature")
    bbu.learn_cycle_status = bbu_data.get("learn_cycle_status")
    bbu.manufacture_date = bbu_data.get("manufacture_date")
    bbu.design_capacity = bbu_data.get("design_capacity")
    bbu.remaining_capacity = bbu_data.get("remaining_capacity")
    bbu.replacement_needed = bool(bbu_data.get("replacement_needed", False))
    bbu.raw_data = bbu_data.get("raw_data")

    next_learn = bbu_data.get("next_learn_time")
    if next_learn and isinstance(next_learn, str):
        try:
            bbu.next_learn_time = datetime.fromisoformat(next_learn)
        except (ValueError, TypeError):
            bbu.next_learn_time = None
    elif isinstance(next_learn, datetime):
        bbu.next_learn_time = next_learn

    await db.flush()
    return bbu


async def _upsert_virtual_drive(
    db: AsyncSession,
    controller_db_id: uuid.UUID,
    vd_data: dict,
) -> VirtualDrive:
    """Upsert a virtual drive record."""
    vd_id = int(vd_data.get("vd_id", 0))

    result = await db.execute(
        select(VirtualDrive).where(
            and_(
                VirtualDrive.controller_id == controller_db_id,
                VirtualDrive.vd_id == vd_id,
            )
        )
    )
    vd = result.scalar_one_or_none()

    if vd is None:
        vd = VirtualDrive(
            controller_id=controller_db_id,
            vd_id=vd_id,
            raid_type=vd_data.get("raid_type", "Unknown"),
            state=vd_data.get("state", "Unknown"),
        )
        db.add(vd)

    vd.dg_id = vd_data.get("dg_id")
    vd.name = vd_data.get("name")
    vd.raid_type = vd_data.get("raid_type", vd.raid_type)
    vd.state = vd_data.get("state", vd.state)
    vd.size = vd_data.get("size")
    vd.size_bytes = vd_data.get("size_bytes")
    vd.strip_size = vd_data.get("strip_size")
    vd.number_of_drives = vd_data.get("number_of_drives")
    vd.cache_policy = vd_data.get("cache_policy")
    vd.io_policy = vd_data.get("io_policy")
    vd.read_policy = vd_data.get("read_policy")
    vd.disk_cache_policy = vd_data.get("disk_cache_policy")
    vd.consistent = vd_data.get("consistent")
    vd.access = vd_data.get("access")
    vd.raw_data = vd_data.get("raw_data")

    await db.flush()
    return vd


async def _upsert_physical_drive(
    db: AsyncSession,
    controller_db_id: uuid.UUID,
    pd_data: dict,
) -> PhysicalDrive:
    """Upsert a physical drive record."""
    enclosure_id = int(pd_data.get("enclosure_id", 0))
    slot_number = int(pd_data.get("slot_number", 0))

    result = await db.execute(
        select(PhysicalDrive).where(
            and_(
                PhysicalDrive.controller_id == controller_db_id,
                PhysicalDrive.enclosure_id == enclosure_id,
                PhysicalDrive.slot_number == slot_number,
            )
        )
    )
    pd = result.scalar_one_or_none()

    if pd is None:
        pd = PhysicalDrive(
            controller_id=controller_db_id,
            enclosure_id=enclosure_id,
            slot_number=slot_number,
            state=pd_data.get("state", "Unknown"),
        )
        db.add(pd)

    pd.device_id = pd_data.get("device_id")
    pd.drive_group = pd_data.get("drive_group")
    pd.state = pd_data.get("state", pd.state)
    pd.size = pd_data.get("size")
    pd.size_bytes = pd_data.get("size_bytes")
    pd.media_type = pd_data.get("media_type")
    pd.interface_type = pd_data.get("interface_type")
    pd.model = pd_data.get("model")
    pd.serial_number = pd_data.get("serial_number")
    pd.firmware_version = pd_data.get("firmware_version")
    pd.manufacturer = pd_data.get("manufacturer")
    pd.sector_size = pd_data.get("sector_size")
    pd.rotation_speed = pd_data.get("rotation_speed")
    pd.temperature = pd_data.get("temperature")
    pd.shield_counter = pd_data.get("shield_counter", 0) or 0
    pd.media_error_count = pd_data.get("media_error_count", 0) or 0
    pd.other_error_count = pd_data.get("other_error_count", 0) or 0
    pd.predictive_failure = pd_data.get("predictive_failure", 0) or 0
    pd.smart_alert = bool(pd_data.get("smart_alert", False))
    pd.smart_data = pd_data.get("smart_data")
    pd.pd_raw_data = pd_data.get("raw_data")

    await db.flush()
    return pd


async def _record_smart_history(
    db: AsyncSession,
    pd_db_id: uuid.UUID,
    pd_data: dict,
) -> SmartHistory | None:
    """Create a SMART history snapshot for a physical drive."""
    smart = pd_data.get("smart_data")
    temperature = pd_data.get("temperature")
    media_errors = pd_data.get("media_error_count")
    other_errors = pd_data.get("other_error_count")
    pred_fail = pd_data.get("predictive_failure")

    if all(v is None for v in [temperature, media_errors, other_errors, pred_fail, smart]):
        return None

    entry = SmartHistory(
        physical_drive_id=pd_db_id,
        temperature=temperature,
        media_error_count=media_errors,
        other_error_count=other_errors,
        predictive_failure=pred_fail,
        reallocated_sectors=smart.get("reallocated_sectors") if smart else None,
        power_on_hours=smart.get("power_on_hours") if smart else None,
        smart_data=smart,
    )
    db.add(entry)
    await db.flush()
    return entry


async def _record_events(
    db: AsyncSession,
    controller_db_id: uuid.UUID,
    events: list[dict],
) -> int:
    """
    Record new controller events, skipping duplicates by event_id.

    Returns:
        Count of newly inserted events.
    """
    if not events:
        return 0

    existing_ids_result = await db.execute(
        select(ControllerEvent.event_id).where(
            ControllerEvent.controller_id == controller_db_id
        )
    )
    existing_event_ids = set(existing_ids_result.scalars().all())

    count = 0
    for evt_data in events:
        evt_id = evt_data.get("event_id")
        if evt_id is not None and evt_id in existing_event_ids:
            continue

        event_time = evt_data.get("event_time")
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time)
            except (ValueError, TypeError):
                event_time = None

        evt = ControllerEvent(
            controller_id=controller_db_id,
            event_id=evt_id,
            event_time=event_time,
            severity=evt_data.get("severity"),
            event_class=evt_data.get("event_class"),
            event_description=evt_data.get("event_description") or evt_data.get("description"),
            event_data=evt_data.get("event_data"),
        )
        db.add(evt)
        count += 1

    if count > 0:
        await db.flush()

    return count


# ---------------------------------------------------------------------------
# Server-level upsert
# ---------------------------------------------------------------------------

async def _upsert_server_info(
    db: AsyncSession,
    server: Server,
    report: dict,
) -> None:
    """Update server metadata from the report."""
    system_info = report.get("system_info", {})
    if system_info:
        server.hostname = system_info.get("hostname", server.hostname)
        server.fqdn = system_info.get("fqdn") or server.fqdn
        server.ip_address = system_info.get("ip_address", server.ip_address)
        server.os_name = system_info.get("os_name") or server.os_name
        server.os_version = system_info.get("os_version") or server.os_version
        server.kernel_version = system_info.get("kernel_version") or server.kernel_version
        server.cpu_model = system_info.get("cpu_model") or server.cpu_model
        server.cpu_cores = system_info.get("cpu_cores") or server.cpu_cores
        server.ram_total_gb = system_info.get("ram_total_gb") or server.ram_total_gb
        server.uptime_seconds = system_info.get("uptime_seconds")
        server.last_os_update = system_info.get("last_os_update") or server.last_os_update

    server.agent_version = report.get("agent_version") or server.agent_version
    server.storcli_version = report.get("storcli_version") or server.storcli_version
    server.last_seen = datetime.now(timezone.utc)
    server.last_report = report
    server.server_info = system_info or server.server_info

    await db.flush()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def process_report(
    db: AsyncSession,
    server_id: uuid.UUID,
    report: dict[str, Any],
) -> Server:
    """
    Process a full agent report and upsert all components.

    The report dict is expected to have the following top-level keys:
    - system_info: dict with hostname, ip, OS info, etc.
    - agent_version: str
    - storcli_version: str
    - controllers: list[dict] each containing:
        - controller_id, model, serial_number, status, ...
        - bbu: dict (optional)
        - virtual_drives: list[dict]
        - physical_drives: list[dict]
        - events: list[dict] (optional)

    Args:
        db: Async database session.
        server_id: UUID of the server to update.
        report: Agent report payload.

    Returns:
        The updated Server instance.

    Raises:
        ValueError: If the server is not found.
    """
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()

    if server is None:
        raise ValueError(f"Server with id={server_id} not found")

    logger.info("Processing report for server %s (%s)", server.hostname, server_id)

    # Update server-level metadata
    await _upsert_server_info(db, server, report)

    # Collect flat lists for status computation
    all_vd_data: list[dict] = []
    all_pd_data: list[dict] = []
    all_ctrl_data: list[dict] = []
    all_bbu_data: list[dict] = []

    controllers_data = report.get("controllers", [])

    for ctrl_data in controllers_data:
        all_ctrl_data.append(ctrl_data)

        # Upsert controller
        ctrl = await _upsert_controller(db, server_id, ctrl_data)

        # Upsert BBU
        bbu_data = ctrl_data.get("bbu")
        if bbu_data:
            all_bbu_data.append(bbu_data)
            await _upsert_bbu(db, ctrl.id, bbu_data)

        # Upsert virtual drives
        for vd_data in ctrl_data.get("virtual_drives", []):
            all_vd_data.append(vd_data)
            await _upsert_virtual_drive(db, ctrl.id, vd_data)

        # Upsert physical drives + SMART history
        for pd_data in ctrl_data.get("physical_drives", []):
            all_pd_data.append(pd_data)
            pd_obj = await _upsert_physical_drive(db, ctrl.id, pd_data)
            await _record_smart_history(db, pd_obj.id, pd_data)

        # Record events
        events_data = ctrl_data.get("events", [])
        new_events_count = await _record_events(db, ctrl.id, events_data)
        if new_events_count > 0:
            logger.info(
                "Recorded %d new events for controller %d on %s",
                new_events_count,
                ctrl.controller_id,
                server.hostname,
            )

    # Compute overall server status
    new_status = _compute_server_status(
        all_ctrl_data, all_vd_data, all_pd_data, all_bbu_data
    )
    server.status = new_status
    await db.flush()

    logger.info(
        "Report processed for %s: status=%s, controllers=%d, vds=%d, pds=%d",
        server.hostname,
        new_status,
        len(all_ctrl_data),
        len(all_vd_data),
        len(all_pd_data),
    )

    # Trigger alert evaluation
    try:
        await alert_engine.evaluate_alerts(db, server)
    except Exception:
        logger.exception("Alert evaluation failed for server %s", server.hostname)

    await db.commit()
    return server
