"""storcli64 data collector for RAID Monitor Agent.

Executes storcli64 commands, parses JSON output, and builds structured
reports for all RAID controllers, virtual drives, physical drives,
events, and battery/capacitor status.
"""

import json
import logging
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default timeout for storcli64 commands (seconds)
STORCLI_TIMEOUT = 60


def run_storcli(storcli_path: str, args: List[str]) -> Dict[str, Any]:
    """Execute storcli64 with given arguments and parse JSON output.

    Args:
        storcli_path: Full path to the storcli64 binary.
        args: List of command-line arguments (e.g., ["/c0", "show", "all", "J"]).

    Returns:
        Parsed JSON dict from storcli64 output.

    Raises:
        RuntimeError: If storcli64 exits with non-zero code or output is not valid JSON.
        FileNotFoundError: If storcli64 binary is not found.
        subprocess.TimeoutExpired: If the command exceeds the timeout.
    """
    cmd = [storcli_path] + args
    logger.debug("Executing: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=STORCLI_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        logger.error("storcli64 binary not found: %s", storcli_path)
        raise
    except subprocess.TimeoutExpired:
        logger.error("storcli64 command timed out after %ds: %s", STORCLI_TIMEOUT, cmd)
        raise

    if result.returncode != 0:
        logger.warning(
            "storcli64 returned exit code %d for command %s: stderr=%s",
            result.returncode,
            " ".join(args),
            result.stderr.strip()[:500] if result.stderr else "(empty)",
        )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(
            f"storcli64 produced no output for command: {' '.join(args)}"
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        # storcli sometimes outputs non-JSON preamble; try to find JSON block
        json_start = stdout.find("{")
        if json_start > 0:
            try:
                data = json.loads(stdout[json_start:])
                logger.debug("Parsed JSON after skipping %d bytes of preamble", json_start)
                return data
            except json.JSONDecodeError:
                pass
        logger.error("Failed to parse storcli64 JSON output: %s", exc)
        raise RuntimeError(f"Invalid JSON from storcli64: {exc}") from exc

    return data


def _get_response_data(raw: Dict[str, Any], controller_idx: int = 0) -> Dict[str, Any]:
    """Extract Response Data from storcli JSON output.

    storcli returns JSON like:
        {"Controllers": [{"Command Status": {...}, "Response Data": {...}}]}

    Args:
        raw: Parsed storcli64 JSON output.
        controller_idx: Index into the Controllers array.

    Returns:
        The Response Data dict, or empty dict if not found.
    """
    controllers = raw.get("Controllers", [])
    if not controllers or controller_idx >= len(controllers):
        return {}

    controller = controllers[controller_idx]

    # Check command status
    cmd_status = controller.get("Command Status", {})
    status = cmd_status.get("Status", "")
    if status.lower() not in ("success", ""):
        description = cmd_status.get("Description", "")
        logger.warning(
            "storcli command status: %s - %s", status, description
        )

    return controller.get("Response Data", {})


def collect_all(storcli_path: str) -> Dict[str, Any]:
    """Run a full collection cycle across all RAID controllers.

    Steps:
        1. Detect controllers via `storcli64 show J`
        2. For each controller, collect:
            - Controller info (show all)
            - Virtual drives (vall show all)
            - Physical drives + SMART (eall/sall show all)
            - Events since reboot
            - Battery/capacitor status
        3. Assemble into a structured report dict.

    Args:
        storcli_path: Full path to the storcli64 binary.

    Returns:
        Complete report dict matching the AgentReportPayload schema.
    """
    report = {
        "controllers": [],
        "collection_timestamp": time.time(),
        "storcli_path": storcli_path,
        "errors": [],
    }

    # Step 1: Detect controllers
    try:
        show_data = run_storcli(storcli_path, ["show", "J"])
    except Exception as exc:
        logger.error("Failed to detect controllers: %s", exc)
        report["errors"].append(f"Controller detection failed: {exc}")
        return report

    response = _get_response_data(show_data)

    # Parse controller list from "System Overview" or "Number of Controllers"
    num_controllers = response.get("Number of Controllers", 0)
    system_overview = response.get("System Overview", [])

    if not num_controllers and system_overview:
        num_controllers = len(system_overview)

    if not num_controllers:
        # Try alternate detection: look for /cx entries
        for key in response:
            if key.startswith("/c") and key[2:].isdigit():
                num_controllers = max(num_controllers, int(key[2:]) + 1)

    if num_controllers == 0:
        logger.warning("No RAID controllers detected")
        report["errors"].append("No RAID controllers detected")
        return report

    logger.info("Detected %d RAID controller(s)", num_controllers)

    # Step 2: Collect data for each controller
    for cx in range(num_controllers):
        controller_report = _collect_controller(storcli_path, cx, report["errors"])
        report["controllers"].append(controller_report)

    return report


def _collect_controller(
    storcli_path: str, cx: int, errors: List[str]
) -> Dict[str, Any]:
    """Collect all data for a single RAID controller.

    Args:
        storcli_path: Path to storcli64 binary.
        cx: Controller index (0-based).
        errors: Shared error list to append failures.

    Returns:
        Controller report dict.
    """
    controller_report = {
        "controller_id": cx,
        "info": {},
        "virtual_drives": [],
        "physical_drives": [],
        "events": [],
        "bbu": {},
    }

    # Controller info — merge into top-level for server schema compatibility
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}", "show", "all", "J"])
        response = _get_response_data(raw)
        info = parse_controller(response)
        controller_report.update(info)
    except Exception as exc:
        msg = f"Failed to collect controller /c{cx} info: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Virtual drives
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}/vall", "show", "all", "J"])
        response = _get_response_data(raw)
        controller_report["virtual_drives"] = parse_virtual_drives(response)
    except Exception as exc:
        msg = f"Failed to collect VDs for /c{cx}: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Physical drives + SMART
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}/eall/sall", "show", "all", "J"])
        response = _get_response_data(raw)
        controller_report["physical_drives"] = parse_physical_drives(response, cx)
    except Exception as exc:
        msg = f"Failed to collect PDs for /c{cx}: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Events since reboot
    try:
        raw = run_storcli(
            storcli_path,
            [f"/c{cx}", "show", "events", "type=sincereboot", "J"],
        )
        response = _get_response_data(raw)
        controller_report["events"] = parse_events(response)
    except Exception as exc:
        msg = f"Failed to collect events for /c{cx}: {exc}"
        logger.warning(msg)
        errors.append(msg)

    # Battery / Capacitor
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}/bbu", "show", "all", "J"])
        response = _get_response_data(raw)
        controller_report["bbu"] = parse_bbu(response, source="bbu")
    except Exception:
        # BBU might not exist; try CacheVault (CV) instead
        try:
            raw = run_storcli(storcli_path, [f"/c{cx}/cv", "show", "all", "J"])
            response = _get_response_data(raw)
            controller_report["bbu"] = parse_bbu(response, source="cv")
        except Exception as exc2:
            msg = f"No BBU/CV found for /c{cx}: {exc2}"
            logger.debug(msg)
            # Not appending to errors - BBU may legitimately not be present

    return controller_report


def parse_controller(response: Dict[str, Any]) -> Dict[str, Any]:
    """Parse controller information from storcli 'show all' response.

    Extracts model, serial number, firmware version, RAID levels,
    memory, temperature, and overall status.

    Args:
        response: The Response Data dict from storcli.

    Returns:
        Structured controller info dict.
    """
    basics = response.get("Basics", {})
    version = response.get("Version", {})
    status = response.get("Status", {})
    hw_cfg = response.get("HwCfg", {})

    return {
        "model": basics.get("Model", ""),
        "serial_number": basics.get("Serial Number", ""),
        "status": status.get("Controller Status", ""),
        "firmware_version": version.get("Firmware Version", ""),
        "bios_version": version.get("BIOS Version", ""),
        "driver_version": version.get("Driver Version", ""),
        "memory_size": hw_cfg.get("On Board Memory Size", ""),
        "roc_temperature": _parse_temperature(
            hw_cfg.get("ROC temperature(Degree Celsius)", "")
        ),
        "alarm_status": hw_cfg.get("Alarm", ""),
        "patrol_read_status": response.get("Patrol Read", {}).get("PR Mode", ""),
        "rebuild_rate": response.get("Rebuild Rate", {}).get(
            "Rebuild Rate", ""
        ) if isinstance(response.get("Rebuild Rate"), dict) else response.get("Rebuild Rate", ""),
        "host_interface": hw_cfg.get("Host Interface", ""),
        "product_name": basics.get("Product Name", ""),
        "supported_raid_levels": _parse_supported_raids(response),
    }


def _parse_temperature(value) -> Optional[float]:
    """Parse temperature value from storcli output.

    Args:
        value: Temperature string (e.g., "45°C", "45 C", "45") or number.

    Returns:
        Temperature as float in Celsius, or None.
    """
    if value is None or value == "":
        return None

    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    # Remove common suffixes
    for suffix in ("°C", " C", "C", "°", " Degree Celsius"):
        text = text.replace(suffix, "")
    text = text.strip()

    try:
        return float(text)
    except ValueError:
        return None


def _parse_supported_raids(response: Dict[str, Any]) -> List[str]:
    """Extract supported RAID levels from controller response.

    Args:
        response: storcli response data.

    Returns:
        List of supported RAID level strings.
    """
    capabilities = response.get("Capabilities", {})
    raid_levels = capabilities.get("Supported RAID Levels", "")

    if isinstance(raid_levels, list):
        return raid_levels
    if isinstance(raid_levels, str) and raid_levels:
        return [r.strip() for r in raid_levels.split(",") if r.strip()]
    return []


def parse_virtual_drives(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse virtual drive information from storcli 'vall show all' response.

    Args:
        response: The Response Data dict from storcli.

    Returns:
        List of virtual drive report dicts.
    """
    vd_list = []

    # VDs can be in several locations depending on storcli version
    vds_raw = response.get("VD LIST", response.get("Virtual Drives", []))
    if not isinstance(vds_raw, list):
        vds_raw = []

    # Detailed VD info may be in separate keys like "VD0 Properties"
    vd_properties = {}
    for key, val in response.items():
        if "Properties" in key and key.startswith("VD"):
            try:
                vd_num = int("".join(filter(str.isdigit, key.split(" ")[0])))
                vd_properties[vd_num] = val if isinstance(val, dict) else {}
            except (ValueError, IndexError):
                pass

    for idx, vd_raw in enumerate(vds_raw):
        vd = _parse_single_vd(vd_raw, idx, vd_properties.get(idx, {}))
        vd_list.append(vd)

    return vd_list


def _parse_single_vd(
    vd_raw: Dict[str, Any],
    idx: int,
    properties: Dict[str, Any],
) -> Dict[str, Any]:
    """Parse a single virtual drive entry.

    Args:
        vd_raw: Raw VD dict from the VD LIST.
        idx: Virtual drive index.
        properties: Additional VD properties dict.

    Returns:
        Structured VD dict.
    """
    # DG/VD field is typically formatted as "0/0"
    dg_vd = str(vd_raw.get("DG/VD", f"0/{idx}"))
    parts = dg_vd.split("/")
    dg = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    vd_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else idx

    state = vd_raw.get("State", vd_raw.get("STATUS", ""))
    raid_type = vd_raw.get("TYPE", vd_raw.get("RAID Level", ""))
    size = vd_raw.get("Size", "")
    name = vd_raw.get("Name", vd_raw.get("Virtual Drive Name", ""))

    return {
        "vd_id": vd_num,
        "dg_id": dg,
        "state": str(state),
        "raid_type": str(raid_type),
        "size": str(size),
        "name": str(name),
        "access": str(vd_raw.get("Access", "")),
        "cache_policy": str(vd_raw.get("Cache", properties.get("Current Cache Policy", ""))),
        "consistent": str(vd_raw.get("Consist", "")),
        "strip_size": str(properties.get("Strip Size", vd_raw.get("Strip Size", ""))),
        "number_of_drives": vd_raw.get("DGs", properties.get("Number of Drives", 0)),
        "os_drive_name": str(properties.get("OS Drive Name", "")),
        "creation_date": str(properties.get("Creation Date", "")),
        "creation_time": str(properties.get("Creation Time", "")),
    }


def parse_physical_drives(
    response: Dict[str, Any], cx: int = 0
) -> List[Dict[str, Any]]:
    """Parse physical drive information from storcli 'eall/sall show all' response.

    Includes SMART attributes and detailed device information.

    Args:
        response: The Response Data dict from storcli.
        cx: Controller index for key lookup.

    Returns:
        List of physical drive report dicts.
    """
    pd_list = []

    # PDs can be in several locations
    pds_raw = response.get("PD LIST", response.get("Physical Drives", []))

    # Also check for "Drive /cx/eall/sall" format
    if not pds_raw:
        for key, val in response.items():
            if key.startswith("Drive /c") and isinstance(val, list):
                pds_raw = val
                break

    if not isinstance(pds_raw, list):
        pds_raw = []

    for pd_raw in pds_raw:
        pd = _parse_single_pd(pd_raw, response, cx)
        pd_list.append(pd)

    return pd_list


def _parse_single_pd(
    pd_raw: Dict[str, Any],
    full_response: Dict[str, Any],
    cx: int,
) -> Dict[str, Any]:
    """Parse a single physical drive entry with SMART data.

    Args:
        pd_raw: Raw PD dict from the PD LIST.
        full_response: Full response data for detailed info lookup.
        cx: Controller index.

    Returns:
        Structured PD dict with SMART attributes.
    """
    # Extract enclosure:slot from EID:Slt field
    eid_slt = str(pd_raw.get("EID:Slt", ":"))
    parts = eid_slt.split(":")
    enclosure = int(parts[0]) if len(parts) > 0 and parts[0].strip().isdigit() else 0
    slot = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 0

    state = pd_raw.get("State", "")
    media_type = pd_raw.get("Med", pd_raw.get("Media Type", ""))
    interface = pd_raw.get("Intf", pd_raw.get("Interface", ""))
    size = pd_raw.get("Size", "")
    model = pd_raw.get("Model", "")
    serial = ""
    firmware = ""
    temperature = None
    smart_attributes = {}

    # Look for detailed info: "Drive /cx/eN/sN - Detailed Information"
    detail_key = f"Drive /c{cx}/e{enclosure}/s{slot} - Detailed Information"
    detailed = full_response.get(detail_key, {})

    if isinstance(detailed, dict):
        # Device attributes key
        attr_key = f"Drive /c{cx}/e{enclosure}/s{slot} Device attributes"
        device_attrs = detailed.get(attr_key, {})
        if isinstance(device_attrs, dict):
            serial = device_attrs.get("SN", device_attrs.get("Serial Number", ""))
            firmware = device_attrs.get("Firmware Revision", "")
            model = device_attrs.get("Model Number", model)
            manufacturer = device_attrs.get("Manufacturer Id", "")
        else:
            manufacturer = ""

        # State attributes
        state_key = f"Drive /c{cx}/e{enclosure}/s{slot} State"
        state_attrs = detailed.get(state_key, {})
        if isinstance(state_attrs, dict):
            temperature = _parse_temperature(
                state_attrs.get("Drive Temperature", "")
            )
            smart_attributes = {
                "media_error_count": _safe_int(state_attrs.get("Media Error Count", 0)),
                "other_error_count": _safe_int(state_attrs.get("Other Error Count", 0)),
                "predictive_failure_count": _safe_int(
                    state_attrs.get("Predictive Failure Count", 0)
                ),
                "smart_alert": str(state_attrs.get("S.M.A.R.T alert flagged by drive", "No")),
                "shield_counter": _safe_int(state_attrs.get("Shield Counter", 0)),
                "drive_temperature": temperature,
            }
    else:
        manufacturer = ""

    # Fallback for serial from PD list entry
    if not serial:
        serial = pd_raw.get("SN", pd_raw.get("Serial Number", ""))

    return {
        "enclosure_id": enclosure,
        "slot_number": slot,
        "state": str(state),
        "media_type": str(media_type),
        "interface": str(interface),
        "size": str(size),
        "model": str(model).strip(),
        "serial": str(serial).strip(),
        "firmware": str(firmware).strip(),
        "manufacturer": str(manufacturer).strip() if manufacturer else "",
        "temperature": temperature,
        "drive_group": _safe_int(pd_raw.get("DG", pd_raw.get("Disk Group", -1))),
        "span": _safe_int(pd_raw.get("Sp", -1)),
        "device_id": _safe_int(pd_raw.get("DID", pd_raw.get("Device Id", -1))),
        "sector_size": str(pd_raw.get("SeSz", pd_raw.get("Sector Size", ""))),
        "smart": smart_attributes,
    }


def parse_events(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse controller events from storcli 'show events' response.

    Args:
        response: The Response Data dict from storcli.

    Returns:
        List of event dicts with timestamp, severity, description, and data.
    """
    events = []

    # Events are typically in "Controller Event Log Entries"
    raw_events = response.get("Controller Event Log Entries", [])

    if not isinstance(raw_events, list):
        # Sometimes it is a dict with numeric keys
        if isinstance(raw_events, dict):
            raw_events = list(raw_events.values())
        else:
            return events

    for evt_raw in raw_events:
        if not isinstance(evt_raw, dict):
            continue

        event = {
            "sequence_number": _safe_int(evt_raw.get("Seq Num", evt_raw.get("SeqNum", 0))),
            "timestamp": str(evt_raw.get("Time Stamp", evt_raw.get("TimeStamp", ""))),
            "severity": str(evt_raw.get("Class", evt_raw.get("Severity", "INFO"))),
            "description": str(evt_raw.get("Event Description", evt_raw.get("Description", ""))),
            "event_data": str(evt_raw.get("Event Data", evt_raw.get("Data", ""))),
            "locale": str(evt_raw.get("Locale", "")),
        }
        events.append(event)

    logger.debug("Parsed %d events", len(events))
    return events


def parse_bbu(response: Dict[str, Any], source: str = "bbu") -> Dict[str, Any]:
    """Parse BBU (Battery Backup Unit) or CacheVault status.

    Args:
        response: The Response Data dict from storcli.
        source: Either 'bbu' or 'cv' indicating the data source.

    Returns:
        BBU/CV status dict.
    """
    result = {
        "type": source.upper(),
        "present": False,
    }

    if not response:
        return result

    result["present"] = True

    if source == "bbu":
        # BBU data parsing
        bbu_status = response.get("BBU Status", {})
        bbu_capacity = response.get("BBU Capacity Info", {})
        bbu_design = response.get("BBU Design Info", {})
        bbu_firmware = response.get("BBU Firmware Status", {})

        if isinstance(bbu_status, dict):
            result.update({
                "voltage_mv": _safe_float(bbu_status.get("Voltage", "")),
                "current_ma": _safe_float(bbu_status.get("Current", "")),
                "temperature": _parse_temperature(bbu_status.get("Temperature", "")),
                "battery_state": str(bbu_status.get("Battery State", "")),
                "charging_status": str(bbu_status.get("Charging Status", "")),
                "learn_cycle_active": str(bbu_status.get("Learn Cycle Active", "")),
            })

        if isinstance(bbu_capacity, dict):
            result.update({
                "relative_charge_pct": _safe_int(
                    bbu_capacity.get("Relative State of Charge", 0)
                ),
                "absolute_charge_pct": _safe_int(
                    bbu_capacity.get("Absolute State of charge", 0)
                ),
                "remaining_capacity_mah": _safe_int(
                    bbu_capacity.get("Remaining Capacity", 0)
                ),
                "full_charge_capacity_mah": _safe_int(
                    bbu_capacity.get("Full Charge Capacity", 0)
                ),
            })

        if isinstance(bbu_design, dict):
            result.update({
                "manufacture_date": str(bbu_design.get("Date of Manufacture", "")),
                "design_capacity_mah": _safe_int(
                    bbu_design.get("Design Capacity", 0)
                ),
                "cycle_count": _safe_int(bbu_design.get("Cycle Count", 0)),
            })

        if isinstance(bbu_firmware, dict):
            result.update({
                "replacement_needed": str(
                    bbu_firmware.get("Battery Replacement required", "No")
                ),
                "remaining_capacity_low": str(
                    bbu_firmware.get("Remaining Capacity Low", "No")
                ),
            })

    elif source == "cv":
        # CacheVault data parsing
        cv_info = response.get("Cachevault_Info", response)
        if isinstance(cv_info, list) and cv_info:
            cv_info = cv_info[0]

        if isinstance(cv_info, dict):
            result.update({
                "temperature": _parse_temperature(cv_info.get("Temp", cv_info.get("Temperature", ""))),
                "state": str(cv_info.get("State", "")),
                "replacement_needed": str(cv_info.get("Replacement required", "No")),
                "write_through_fail": str(
                    cv_info.get("Write Through Mode on Drive Failure", "")
                ),
            })

        # CacheVault firmware info
        cv_firmware = response.get("Firmware_Status", {})
        if isinstance(cv_firmware, dict):
            result.update({
                "firmware_version": str(cv_firmware.get("Firmware Version", "")),
                "health_status": str(cv_firmware.get("Health", "")),
            })

    return result


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a value to int, returning default on failure.

    Args:
        value: Value to convert.
        default: Default value if conversion fails.

    Returns:
        Integer value.
    """
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        # Handle strings like "123 MB" by taking the first numeric part
        text = str(value).strip().split()[0] if str(value).strip() else ""
        return int(text)
    except (ValueError, IndexError):
        return default


def _safe_float(value, default: float = 0.0) -> float:
    """Safely convert a value to float, returning default on failure.

    Args:
        value: Value to convert.
        default: Default value if conversion fails.

    Returns:
        Float value.
    """
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip()
        # Remove common unit suffixes
        for suffix in (" mV", " mA", " V", " A", "mV", "mA"):
            text = text.replace(suffix, "")
        return float(text.strip())
    except ValueError:
        return default
