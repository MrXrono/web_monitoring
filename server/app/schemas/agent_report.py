from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime


class OSInfo(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    kernel: Optional[str] = None


class AgentRegisterRequest(BaseModel):
    hostname: str
    ip_address: str
    os: Optional[OSInfo] = None


class AgentRegisterResponse(BaseModel):
    api_key: str
    server_id: str


class BbuReport(BaseModel):
    bbu_type: Optional[str] = None
    state: Optional[str] = None
    temperature: Optional[int] = None
    voltage: Optional[str] = None
    replacement_needed: Optional[bool] = False
    learn_cycle_status: Optional[str] = None
    remaining_capacity: Optional[str] = None
    capacitance: Optional[str] = None
    pack_energy: Optional[str] = None
    manufacture_date: Optional[str] = None
    flash_size: Optional[str] = None
    raw: Optional[dict] = None


class VdReport(BaseModel):
    vd_id: int
    dg_id: Optional[int] = None
    name: Optional[str] = None
    raid_type: str = "Unknown"
    state: str = "Unknown"
    size: Optional[str] = None
    strip_size: Optional[str] = None
    number_of_drives: Optional[int] = None
    cache_policy: Optional[str] = None
    io_policy: Optional[str] = None
    read_policy: Optional[str] = None
    disk_cache: Optional[str] = None
    consistent: Optional[bool] = None
    access: Optional[str] = None
    active_operations: Optional[str] = None
    write_cache: Optional[str] = None
    span_depth: Optional[int] = None
    raw: Optional[dict] = None


class PdReport(BaseModel):
    enclosure_id: int
    slot_number: int
    device_id: Optional[int] = None
    drive_group: Optional[int] = None
    state: str = "Unknown"
    size: Optional[str] = None
    media_type: Optional[str] = None
    interface: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    firmware: Optional[str] = None
    manufacturer: Optional[str] = None
    temperature: Optional[int] = None
    media_error_count: Optional[int] = 0
    other_error_count: Optional[int] = 0
    predictive_failure: Optional[int] = 0
    smart_alert: Optional[bool] = False
    link_speed: Optional[str] = None
    device_speed: Optional[str] = None
    physical_sector_size: Optional[str] = None
    wwn: Optional[str] = None
    smart: Optional[dict] = None
    raw: Optional[dict] = None


class EventReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    seq_num: Optional[int] = Field(None, alias="event_id")
    time: Optional[str] = Field(None, alias="event_time")
    severity: Optional[str] = None
    event_class: Optional[str] = None
    description: Optional[str] = Field(None, alias="event_description")
    raw: Optional[dict] = Field(None, alias="event_data")


class ControllerReport(BaseModel):
    controller_id: int
    model: Optional[str] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    bios_version: Optional[str] = None
    driver_version: Optional[str] = None
    status: Optional[str] = None
    memory_size: Optional[str] = None
    memory_correctable_errors: Optional[int] = 0
    memory_uncorrectable_errors: Optional[int] = 0
    roc_temperature: Optional[int] = None
    rebuild_rate: Optional[int] = None
    patrol_read_status: Optional[str] = None
    cc_status: Optional[str] = None
    alarm_status: Optional[str] = None
    host_interface: Optional[str] = None
    product_name: Optional[str] = None
    supported_raid_levels: Optional[list] = None
    next_cc_launch: Optional[str] = None
    next_pr_launch: Optional[str] = None
    next_battery_learn: Optional[str] = None
    ecc_bucket_count: Optional[int] = 0
    firmware_package_build: Optional[str] = None
    driver_name: Optional[str] = None
    bbu: Optional[BbuReport] = None
    virtual_drives: list[VdReport] = []
    physical_drives: list[PdReport] = []
    events: list[EventReport] = []
    raw: Optional[dict] = None


class AgentReportPayload(BaseModel):
    agent_version: Optional[str] = None
    storcli_version: Optional[str] = None
    hostname: str
    fqdn: Optional[str] = None
    ip_address: str
    os: Optional[OSInfo] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_total_gb: Optional[float] = None
    uptime_seconds: Optional[int] = None
    last_os_update: Optional[str] = None
    collected_at: Optional[str] = None
    controllers: list[ControllerReport] = []


class AgentConfigResponse(BaseModel):
    debug: bool = False
    collection_interval: int = 600
    commands: list[dict] = []


class AgentUpdateCheckResponse(BaseModel):
    latest_version: Optional[str] = None
    current_version: Optional[str] = None
    update_available: bool = False
    sha256: Optional[str] = None
