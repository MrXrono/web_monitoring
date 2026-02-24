from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ---------- Controller sub-schemas ----------

class BbuResponse(BaseModel):
    id: str
    bbu_type: Optional[str] = None
    state: Optional[str] = None
    voltage: Optional[str] = None
    temperature: Optional[int] = None
    learn_cycle_status: Optional[str] = None
    replacement_needed: bool = False

    model_config = {"from_attributes": True}


class VirtualDriveResponse(BaseModel):
    id: str
    vd_id: int
    dg_id: Optional[int] = None
    name: Optional[str] = None
    raid_type: str
    state: str
    size: Optional[str] = None
    strip_size: Optional[str] = None
    number_of_drives: Optional[int] = None
    cache_policy: Optional[str] = None
    io_policy: Optional[str] = None
    read_policy: Optional[str] = None
    disk_cache_policy: Optional[str] = None
    consistent: Optional[bool] = None
    access: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class PhysicalDriveResponse(BaseModel):
    id: str
    enclosure_id: int
    slot_number: int
    device_id: Optional[int] = None
    drive_group: Optional[int] = None
    state: str
    size: Optional[str] = None
    media_type: Optional[str] = None
    interface_type: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    manufacturer: Optional[str] = None
    temperature: Optional[int] = None
    media_error_count: int = 0
    other_error_count: int = 0
    predictive_failure: int = 0
    smart_alert: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class EventResponse(BaseModel):
    id: int
    event_id: Optional[int] = None
    event_time: Optional[datetime] = None
    severity: Optional[str] = None
    event_class: Optional[str] = None
    event_description: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ControllerResponse(BaseModel):
    id: str
    controller_id: int
    model: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    bios_version: Optional[str] = None
    driver_version: Optional[str] = None
    status: Optional[str] = None
    memory_size: Optional[str] = None
    memory_correctable_errors: int = 0
    memory_uncorrectable_errors: int = 0
    roc_temperature: Optional[int] = None
    rebuild_rate: Optional[int] = None
    patrol_read_status: Optional[str] = None
    cc_status: Optional[str] = None
    alarm_status: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ControllerDetailResponse(ControllerResponse):
    bbu: Optional[BbuResponse] = None
    virtual_drives: list[VirtualDriveResponse] = []
    physical_drives: list[PhysicalDriveResponse] = []


# ---------- Server schemas ----------

class ServerListItem(BaseModel):
    id: str
    hostname: str
    fqdn: Optional[str] = None
    ip_address: str
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    status: str
    debug_mode: bool = False
    last_seen: Optional[datetime] = None
    controller_count: int = 0
    vd_count: int = 0
    pd_count: int = 0
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ServerListResponse(BaseModel):
    items: list[ServerListItem]
    total: int
    page: int
    per_page: int
    pages: int


class ServerDetailResponse(BaseModel):
    id: str
    hostname: str
    fqdn: Optional[str] = None
    ip_address: str
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    agent_version: Optional[str] = None
    storcli_version: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_total_gb: Optional[float] = None
    uptime_seconds: Optional[int] = None
    last_os_update: Optional[str] = None
    status: str
    debug_mode: bool = False
    notes: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    controllers: list[ControllerDetailResponse] = []

    model_config = {"from_attributes": True}


class SmartHistoryEntry(BaseModel):
    id: int
    recorded_at: Optional[datetime] = None
    temperature: Optional[int] = None
    media_error_count: Optional[int] = None
    other_error_count: Optional[int] = None
    predictive_failure: Optional[int] = None
    reallocated_sectors: Optional[int] = None
    power_on_hours: Optional[int] = None
    smart_data: Optional[dict] = None

    model_config = {"from_attributes": True}


class SmartHistoryResponse(BaseModel):
    items: list[SmartHistoryEntry]
    total: int


class EventListResponse(BaseModel):
    items: list[EventResponse]
    total: int
    page: int
    per_page: int
    pages: int
