import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta
from app.config import MSK
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
import bcrypt as _bcrypt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.dependencies import get_db, verify_agent_key
from app.models.api_key import ApiKey
from app.models.server import Server
from app.models.controller import Controller
from app.models.bbu import BbuUnit
from app.models.virtual_drive import VirtualDrive
from app.models.physical_drive import PhysicalDrive
from app.models.smart_history import SmartHistory
from app.models.event import ControllerEvent
from app.models.agent_package import AgentPackage
from app.models.setting import Setting
from app.models.software_raid import SoftwareRaid
from app.schemas.agent_report import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentReportPayload,
    AgentConfigResponse,
    AgentUpdateCheckResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["agent"])


@router.post("/register", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    payload: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new agent. Creates a Server record and an API key.
    If a server with this hostname already exists, regenerates its API key.
    Returns the raw API key (shown only once) and the server ID.
    """
    # Check if server with this hostname already exists
    result = await db.execute(
        select(Server).where(Server.hostname == payload.hostname)
    )
    server = result.scalar_one_or_none()

    if server is None:
        server = Server(
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            os_name=payload.os.name if payload.os else None,
            os_version=payload.os.version if payload.os else None,
            kernel_version=payload.os.kernel if payload.os else None,
            status="registered",
        )
        db.add(server)
        await db.flush()
    else:
        # Update IP and OS info
        server.ip_address = payload.ip_address
        if payload.os:
            server.os_name = payload.os.name
            server.os_version = payload.os.version
            server.kernel_version = payload.os.kernel

        # Remove old API key if exists
        result = await db.execute(
            select(ApiKey).where(ApiKey.server_id == server.id)
        )
        old_key = result.scalar_one_or_none()
        if old_key:
            await db.delete(old_key)
            await db.flush()

    # Generate new API key
    raw_key = secrets.token_urlsafe(48)
    key_hash = _bcrypt.hashpw(raw_key.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")
    key_prefix = raw_key[:8]

    api_key = ApiKey(
        server_id=server.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()

    return AgentRegisterResponse(
        api_key=raw_key,
        server_id=str(server.id),
    )


@router.post("/report", status_code=status.HTTP_200_OK)
async def receive_report(
    payload: AgentReportPayload,
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """
    Receive a full status report from an agent.
    Updates server metadata, controllers, VDs, PDs, BBU, events, and SMART history.
    """
    now = datetime.now(MSK)

    # Update server metadata
    server.hostname = payload.hostname
    server.fqdn = payload.fqdn
    server.ip_address = payload.ip_address
    server.agent_version = payload.agent_version
    server.storcli_version = payload.storcli_version
    server.smartctl_version = payload.smartctl_version
    server.cpu_model = payload.cpu_model
    server.cpu_cores = payload.cpu_cores
    server.ram_total_gb = payload.ram_total_gb
    server.uptime_seconds = payload.uptime_seconds
    server.last_os_update = payload.last_os_update
    server.last_seen = now
    server.status = "online"

    if payload.os:
        server.os_name = payload.os.name
        server.os_version = payload.os.version
        server.kernel_version = payload.os.kernel

    # Store the raw report JSON
    server.last_report = payload.model_dump(mode="json")

    # Process controllers
    for ctrl_report in payload.controllers:
        # Find or create controller
        result = await db.execute(
            select(Controller).where(
                Controller.server_id == server.id,
                Controller.controller_id == ctrl_report.controller_id,
            )
        )
        controller = result.scalar_one_or_none()

        if controller is None:
            controller = Controller(
                server_id=server.id,
                controller_id=ctrl_report.controller_id,
            )
            db.add(controller)
            await db.flush()

        # Update controller fields
        controller.model = ctrl_report.model
        controller.serial_number = ctrl_report.serial_number
        controller.firmware_version = ctrl_report.firmware_version
        controller.bios_version = ctrl_report.bios_version
        controller.driver_version = ctrl_report.driver_version
        controller.status = ctrl_report.status
        controller.memory_size = ctrl_report.memory_size
        controller.memory_correctable_errors = ctrl_report.memory_correctable_errors or 0
        controller.memory_uncorrectable_errors = ctrl_report.memory_uncorrectable_errors or 0
        controller.roc_temperature = ctrl_report.roc_temperature
        controller.rebuild_rate = ctrl_report.rebuild_rate
        controller.patrol_read_status = ctrl_report.patrol_read_status
        controller.cc_status = ctrl_report.cc_status
        controller.alarm_status = ctrl_report.alarm_status
        controller.host_interface = ctrl_report.host_interface
        controller.product_name = ctrl_report.product_name
        controller.supported_raid_levels = ctrl_report.supported_raid_levels
        controller.next_cc_launch = ctrl_report.next_cc_launch
        controller.next_pr_launch = ctrl_report.next_pr_launch
        controller.next_battery_learn = ctrl_report.next_battery_learn
        controller.ecc_bucket_count = ctrl_report.ecc_bucket_count or 0
        controller.firmware_package_build = ctrl_report.firmware_package_build
        controller.driver_name = ctrl_report.driver_name
        controller.raw_data = ctrl_report.raw

        # Process BBU
        if ctrl_report.bbu:
            result = await db.execute(
                select(BbuUnit).where(BbuUnit.controller_id == controller.id)
            )
            bbu = result.scalar_one_or_none()
            if bbu is None:
                bbu = BbuUnit(controller_id=controller.id)
                db.add(bbu)

            bbu.bbu_type = ctrl_report.bbu.bbu_type
            bbu.state = ctrl_report.bbu.state
            bbu.temperature = ctrl_report.bbu.temperature
            bbu.voltage = ctrl_report.bbu.voltage
            bbu.replacement_needed = ctrl_report.bbu.replacement_needed or False
            bbu.learn_cycle_status = ctrl_report.bbu.learn_cycle_status
            bbu.remaining_capacity = ctrl_report.bbu.remaining_capacity
            bbu.capacitance = ctrl_report.bbu.capacitance
            bbu.pack_energy = ctrl_report.bbu.pack_energy
            bbu.design_capacity = ctrl_report.bbu.design_capacity
            bbu.manufacture_date = ctrl_report.bbu.manufacture_date
            bbu.flash_size = ctrl_report.bbu.flash_size
            bbu.raw_data = ctrl_report.bbu.raw

        # Process Virtual Drives
        existing_vd_ids = set()
        for vd_report in ctrl_report.virtual_drives:
            existing_vd_ids.add(vd_report.vd_id)
            result = await db.execute(
                select(VirtualDrive).where(
                    VirtualDrive.controller_id == controller.id,
                    VirtualDrive.vd_id == vd_report.vd_id,
                )
            )
            vd = result.scalar_one_or_none()
            if vd is None:
                vd = VirtualDrive(
                    controller_id=controller.id,
                    vd_id=vd_report.vd_id,
                    raid_type=vd_report.raid_type,
                    state=vd_report.state,
                )
                db.add(vd)
            else:
                vd.raid_type = vd_report.raid_type
                vd.state = vd_report.state

            vd.dg_id = vd_report.dg_id
            vd.name = vd_report.name
            vd.size = vd_report.size
            vd.strip_size = vd_report.strip_size
            vd.number_of_drives = vd_report.number_of_drives
            vd.cache_policy = vd_report.cache_policy
            vd.io_policy = vd_report.io_policy
            vd.read_policy = vd_report.read_policy
            vd.disk_cache_policy = vd_report.disk_cache
            vd.consistent = vd_report.consistent
            vd.access = vd_report.access
            vd.active_operations = vd_report.active_operations
            vd.write_cache = vd_report.write_cache
            vd.span_depth = vd_report.span_depth
            vd.raw_data = vd_report.raw

        # Remove VDs that no longer exist on the controller
        result = await db.execute(
            select(VirtualDrive).where(
                VirtualDrive.controller_id == controller.id,
                VirtualDrive.vd_id.notin_(existing_vd_ids) if existing_vd_ids else True,
            )
        )
        for stale_vd in result.scalars().all():
            if stale_vd.vd_id not in existing_vd_ids:
                await db.delete(stale_vd)

        # Process Physical Drives
        existing_pd_keys = set()
        for pd_report in ctrl_report.physical_drives:
            pd_key = (pd_report.enclosure_id, pd_report.slot_number)
            existing_pd_keys.add(pd_key)

            result = await db.execute(
                select(PhysicalDrive).where(
                    PhysicalDrive.controller_id == controller.id,
                    PhysicalDrive.enclosure_id == pd_report.enclosure_id,
                    PhysicalDrive.slot_number == pd_report.slot_number,
                )
            )
            pd = result.scalar_one_or_none()
            if pd is None:
                pd = PhysicalDrive(
                    controller_id=controller.id,
                    enclosure_id=pd_report.enclosure_id,
                    slot_number=pd_report.slot_number,
                    state=pd_report.state,
                )
                db.add(pd)
                await db.flush()
            else:
                pd.state = pd_report.state

            pd.device_id = pd_report.device_id
            pd.drive_group = pd_report.drive_group
            pd.size = pd_report.size
            pd.media_type = pd_report.media_type
            pd.interface_type = pd_report.interface
            pd.model = pd_report.model
            pd.serial_number = pd_report.serial
            pd.firmware_version = pd_report.firmware
            pd.manufacturer = pd_report.manufacturer
            pd.temperature = pd_report.temperature
            pd.media_error_count = pd_report.media_error_count or 0
            pd.other_error_count = pd_report.other_error_count or 0
            pd.predictive_failure = pd_report.predictive_failure or 0
            pd.smart_alert = pd_report.smart_alert or False
            pd.link_speed = pd_report.link_speed
            pd.device_speed = pd_report.device_speed
            pd.physical_sector_size = pd_report.physical_sector_size
            pd.wwn = pd_report.wwn
            pd.smart_data = pd_report.smart
            pd.pd_raw_data = pd_report.raw

            # Record SMART history snapshot
            smart_entry = SmartHistory(
                physical_drive_id=pd.id,
                recorded_at=now,
                temperature=pd_report.temperature,
                media_error_count=pd_report.media_error_count,
                other_error_count=pd_report.other_error_count,
                predictive_failure=pd_report.predictive_failure,
                smart_data=pd_report.smart,
            )
            db.add(smart_entry)

        # Process Events
        for event_report in ctrl_report.events:
            # Check for duplicate by seq_num
            if event_report.seq_num is not None:
                result = await db.execute(
                    select(ControllerEvent).where(
                        ControllerEvent.controller_id == controller.id,
                        ControllerEvent.event_id == event_report.seq_num,
                    )
                )
                if result.scalar_one_or_none() is not None:
                    continue

            event = ControllerEvent(
                controller_id=controller.id,
                event_id=event_report.seq_num,
                severity=event_report.severity,
                event_class=event_report.event_class,
                event_description=event_report.description,
                event_data=event_report.raw,
            )
            # Parse event time if provided
            if event_report.time:
                try:
                    event.event_time = datetime.fromisoformat(event_report.time)
                except (ValueError, TypeError):
                    event.event_time = now

            db.add(event)

    # Process Software RAID arrays (mdadm)
    reported_array_names = set()
    for sw_report in payload.software_raid:
        reported_array_names.add(sw_report.array_name)
        result = await db.execute(
            select(SoftwareRaid).where(
                SoftwareRaid.server_id == server.id,
                SoftwareRaid.array_name == sw_report.array_name,
            )
        )
        sw_raid = result.scalar_one_or_none()
        if sw_raid is None:
            sw_raid = SoftwareRaid(
                server_id=server.id,
                array_name=sw_report.array_name,
            )
            db.add(sw_raid)

        sw_raid.raid_level = sw_report.raid_level
        sw_raid.state = sw_report.state or "unknown"
        sw_raid.array_size = sw_report.array_size
        sw_raid.num_devices = sw_report.num_devices
        sw_raid.active_devices = sw_report.active_devices
        sw_raid.working_devices = sw_report.working_devices
        sw_raid.failed_devices = sw_report.failed_devices
        sw_raid.spare_devices = sw_report.spare_devices
        sw_raid.rebuild_progress = sw_report.rebuild_progress
        sw_raid.uuid_str = sw_report.uuid
        sw_raid.creation_time = sw_report.creation_time
        sw_raid.member_devices = [m.model_dump() for m in sw_report.member_devices]
        sw_raid.raw_data = sw_report.raw

    # Remove stale software RAID arrays no longer reported
    if reported_array_names:
        result = await db.execute(
            select(SoftwareRaid).where(
                SoftwareRaid.server_id == server.id,
                SoftwareRaid.array_name.notin_(reported_array_names),
            )
        )
    else:
        result = await db.execute(
            select(SoftwareRaid).where(SoftwareRaid.server_id == server.id)
        )
    for stale_sw in result.scalars().all():
        await db.delete(stale_sw)

    # Compute server status based on hardware health
    status = "ok"

    # Check hardware RAID controllers
    for ctrl_report in payload.controllers:
        if ctrl_report.status and ctrl_report.status.lower() not in ("optimal", "ok", "good"):
            status = "critical"
        for vd in ctrl_report.virtual_drives:
            vd_state = (vd.state or "").lower()
            if vd_state in ("dgrd", "degraded"):
                status = "critical"
            elif vd_state in ("rbld", "rebuilding") and status != "critical":
                status = "warning"
        for pd in ctrl_report.physical_drives:
            pd_state = (pd.state or "").lower()
            if pd_state in ("failed", "offline", "ubad"):
                status = "critical"
            elif pd.predictive_failure and pd.predictive_failure > 0 and status != "critical":
                status = "warning"
            elif pd.smart_alert and status != "critical":
                status = "warning"

    # Check software RAID arrays
    for sw_report in payload.software_raid:
        sw_state = (sw_report.state or "").lower()
        if sw_state in ("degraded", "inactive"):
            status = "critical"
        elif "rebuild" in sw_state and status != "critical":
            status = "warning"
        if sw_report.failed_devices and sw_report.failed_devices > 0:
            status = "critical"

    server.status = status

    await db.commit()

    return {"status": "ok", "message": "Report processed"}


@router.get("/config", response_model=AgentConfigResponse)
async def get_agent_config(
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """Return agent configuration: debug mode, collection interval, and pending commands."""
    # Get collection interval from settings
    result = await db.execute(
        select(Setting).where(Setting.key == "agent_collection_interval")
    )
    interval_setting = result.scalar_one_or_none()
    interval = 600
    if interval_setting and interval_setting.value:
        try:
            interval = int(interval_setting.value)
        except ValueError:
            pass

    return AgentConfigResponse(
        debug=server.debug_mode,
        collection_interval=interval,
        commands=[],
    )


@router.get("/update/check", response_model=AgentUpdateCheckResponse)
async def check_agent_update(
    request: Request,
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """Check if an agent update is available."""
    result = await db.execute(
        select(AgentPackage)
        .where(AgentPackage.is_current.is_(True))
        .order_by(AgentPackage.uploaded_at.desc())
        .limit(1)
    )
    current_pkg = result.scalar_one_or_none()

    if current_pkg is None:
        return AgentUpdateCheckResponse(
            latest_version=None,
            current_version=server.agent_version,
            update_available=False,
        )

    # Compare versions using semver-like parsing
    update_available = False
    agent_ver_str = server.agent_version or "0.0.0"
    if current_pkg.version != agent_ver_str:
        try:
            agent_ver = tuple(int(p) for p in agent_ver_str.split("."))
            pkg_ver = tuple(int(p) for p in current_pkg.version.split("."))
            update_available = pkg_ver > agent_ver
        except (ValueError, AttributeError):
            update_available = current_pkg.version != agent_ver_str

    # Build absolute download URL so the agent can use it directly
    base_url = str(request.base_url).rstrip("/")
    download_url = f"{base_url}/api/v1/agent/update/download"

    return AgentUpdateCheckResponse(
        latest_version=current_pkg.version,
        current_version=server.agent_version,
        update_available=update_available,
        sha256=current_pkg.file_hash_sha256,
        # Fields required by agent updater.py
        version=current_pkg.version,
        download_url=download_url,
        size=current_pkg.file_size,
    )


@router.get("/update/download")
async def download_agent_update(
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """Download the latest agent RPM package."""
    from fastapi.responses import FileResponse

    result = await db.execute(
        select(AgentPackage)
        .where(AgentPackage.is_current.is_(True))
        .order_by(AgentPackage.uploaded_at.desc())
        .limit(1)
    )
    pkg = result.scalar_one_or_none()

    if pkg is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No agent package available",
        )

    file_path = Path(pkg.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent package file not found on disk",
        )

    return FileResponse(
        path=str(file_path),
        filename=pkg.filename,
        media_type="application/x-rpm",
    )


@router.get("/storcli/download")
async def download_storcli(
    server: Server = Depends(verify_agent_key),
):
    """Download the storcli64 RPM package."""
    from fastapi.responses import FileResponse

    storcli_dir = Path(settings.STORCLI_PACKAGES_DIR)
    if not storcli_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No storcli packages directory found",
        )

    # Find the latest RPM in the directory
    rpm_files = sorted(storcli_dir.glob("*.rpm"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not rpm_files:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No storcli RPM found",
        )

    rpm_file = rpm_files[0]
    return FileResponse(
        path=str(rpm_file),
        filename=rpm_file.name,
        media_type="application/x-rpm",
    )


def _cleanup_old_agent_logs(logs_dir: Path, max_age_days: int = 7) -> int:
    """Delete agent log files older than max_age_days. Returns count of deleted files."""
    if not logs_dir.exists():
        return 0
    cutoff = datetime.now().timestamp() - (max_age_days * 86400)
    deleted = 0
    for f in logs_dir.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                deleted += 1
            except OSError:
                pass
    return deleted


@router.post("/logs/upload", status_code=status.HTTP_200_OK)
async def upload_agent_logs(
    file: UploadFile = File(...),
    server: Server = Depends(verify_agent_key),
):
    """Receive log files uploaded by an agent."""
    uploads_dir = Path(settings.UPLOADS_DIR) / "agent_logs" / str(server.id)
    uploads_dir.mkdir(parents=True, exist_ok=True)

    # Clean old logs from this agent (older than 7 days)
    cleaned = _cleanup_old_agent_logs(uploads_dir)
    if cleaned:
        logger.info("Cleaned %d old log files for agent %s", cleaned, server.hostname)

    timestamp = datetime.now(MSK).strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{server.hostname}_{timestamp}_{file.filename}"
    file_path = uploads_dir / safe_filename

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    logger.info("Agent %s uploaded logs: %s (%d bytes)", server.hostname, safe_filename, len(content))

    return {"status": "ok", "filename": safe_filename, "size": len(content)}


@router.get("/commands")
async def get_pending_commands(
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """Get pending commands for this agent."""
    # Commands could be stored in server_info JSON or a dedicated table.
    # For now return from server_info.commands if present.
    commands = []
    if server.server_info and isinstance(server.server_info, dict):
        commands = server.server_info.get("pending_commands", [])

    return {"commands": commands}


@router.post("/commands/{cmd_id}/ack", status_code=status.HTTP_200_OK)
async def acknowledge_command(
    cmd_id: str,
    server: Server = Depends(verify_agent_key),
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge that a command has been executed by the agent."""
    if server.server_info and isinstance(server.server_info, dict):
        pending = server.server_info.get("pending_commands", [])
        updated = [cmd for cmd in pending if cmd.get("id") != cmd_id]

        # Record in executed list
        executed = server.server_info.get("executed_commands", [])
        for cmd in pending:
            if cmd.get("id") == cmd_id:
                cmd["acked_at"] = datetime.now(MSK).isoformat()
                executed.append(cmd)
                break

        server.server_info = {
            **server.server_info,
            "pending_commands": updated,
            "executed_commands": executed[-50:],  # Keep last 50
        }
        await db.commit()

    return {"status": "ok", "message": f"Command {cmd_id} acknowledged"}
