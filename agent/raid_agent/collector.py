"""storcli64 data collector for RAID Monitor Agent.

Executes storcli64 commands, parses JSON output, and builds structured
reports for all RAID controllers, virtual drives, physical drives,
events, and battery/capacitor status.
"""

import json
import logging
import re
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


def _run_storcli_text(storcli_path: str, args: List[str]) -> str:
    """Execute storcli64 and return raw text output (no JSON parsing).

    Used for commands like 'show events' that may not produce valid JSON.
    """
    cmd = [storcli_path] + args
    logger.debug("Executing (text mode): %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=STORCLI_TIMEOUT,
        check=False,
    )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"storcli64 produced no output for command: {' '.join(args)}")

    return stdout


def get_storcli_version(storcli_path: str) -> str:
    """Get storcli64 version string by running ``storcli64 -v``.

    Returns:
        Version string (e.g. '007.2705.0000.0000') or empty string on failure.
    """
    try:
        output = _run_storcli_text(storcli_path, ["-v"])
        # Example: "StorCli SAS Customization Utility Ver 007.2705.0000.0000 August 24, 2023"
        match = re.search(r"Ver\s+([\d.]+)", output)
        if match:
            return match.group(1)
        # Fallback: return first line that contains version info
        for line in output.splitlines():
            if "ver" in line.lower():
                return line.strip()
    except Exception as exc:
        logger.debug("Failed to get storcli version: %s", exc)
    return ""


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
    ctrl_response = {}
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}", "show", "all", "J"])
        ctrl_response = _get_response_data(raw)
        info = parse_controller(ctrl_response)
        controller_report.update(info)
    except Exception as exc:
        msg = f"Failed to collect controller /c{cx} info: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Virtual drives
    vd_response = {}
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}/vall", "show", "all", "J"])
        controllers_arr = raw.get("Controllers", [])
        logger.info("VD vall returned %d Controllers entries for /c%d", len(controllers_arr), cx)
        all_vds = []
        for ci, ctrl_entry in enumerate(controllers_arr):
            response = ctrl_entry.get("Response Data", {})
            if ci == 0:
                vd_response = response  # save for PD fallback
                logger.info("VD response keys[0] for /c%d: %s", cx, list(response.keys())[:10])
            vds = parse_virtual_drives(response)
            all_vds.extend(vds)
        controller_report["virtual_drives"] = all_vds
        logger.info("Collected %d VDs for /c%d", len(all_vds), cx)
    except Exception as exc:
        msg = f"Failed to collect VDs for /c{cx}: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Physical drives + SMART
    try:
        raw = run_storcli(storcli_path, [f"/c{cx}/eall/sall", "show", "all", "J"])
        controllers_arr = raw.get("Controllers", [])
        logger.info("PD eall/sall returned %d Controllers entries for /c%d", len(controllers_arr), cx)
        all_pds = []
        for ci, ctrl_entry in enumerate(controllers_arr):
            response = ctrl_entry.get("Response Data", {})
            if ci == 0:
                logger.info("PD response keys[0] for /c%d: %s", cx, list(response.keys())[:10])
            pds = parse_physical_drives(response, cx)
            all_pds.extend(pds)
        # Deduplicate by (enclosure_id, slot_number)
        seen = set()
        deduped = []
        for pd in all_pds:
            key = (pd["enclosure_id"], pd["slot_number"])
            if key not in seen:
                seen.add(key)
                deduped.append(pd)
        controller_report["physical_drives"] = deduped
        logger.info("Collected %d PDs for /c%d (from eall/sall)", len(deduped), cx)
    except Exception as exc:
        msg = f"Failed to collect PDs for /c{cx}: {exc}"
        logger.error(msg)
        errors.append(msg)

    # Fallback: if no PDs found, try extracting from VD response ("PDs for VD N" keys)
    if not controller_report["physical_drives"] and vd_response:
        logger.info("No PDs from eall/sall, trying VD response fallback for /c%d", cx)
        controller_report["physical_drives"] = parse_physical_drives(vd_response, cx)
        logger.info("Collected %d PDs for /c%d (from VD fallback)", len(controller_report["physical_drives"]), cx)

    # Events since reboot
    try:
        raw = run_storcli(
            storcli_path,
            [f"/c{cx}", "show", "events", "type=sincereboot", "J"],
        )
        response = _get_response_data(raw)
        controller_report["events"] = parse_events(response)
    except Exception:
        # JSON events often fail on storcli7 — fall back to text parsing
        try:
            events_text = _run_storcli_text(
                storcli_path,
                [f"/c{cx}", "show", "events", "type=sincereboot"],
            )
            controller_report["events"] = parse_events_text(events_text)
            logger.info(
                "Parsed %d events from text output for /c%d",
                len(controller_report["events"]), cx,
            )
        except Exception as exc:
            msg = f"Failed to collect events for /c{cx}: {exc}"
            logger.warning(msg)
            errors.append(msg)

    # Compute approximate timestamps for events that only have
    # "Seconds since last reboot" (early boot events before clock sync)
    _resolve_relative_event_times(controller_report["events"])

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

    # Supplement or replace BBU data with CacheVault info from controller show all
    if ctrl_response:
        cv_fallback = _parse_cachevault_from_controller(ctrl_response)
        if cv_fallback:
            bbu_data = controller_report["bbu"]
            if not bbu_data or not bbu_data.get("state"):
                # No useful BBU data — use CacheVault info entirely
                controller_report["bbu"] = cv_fallback
                logger.info("Using CacheVault info from controller show all for /c%d", cx)
            else:
                # Supplement with specific model info if missing
                if not bbu_data.get("bbu_type") or bbu_data["bbu_type"] in ("BBU", "CV"):
                    bbu_data["bbu_type"] = cv_fallback.get("bbu_type", bbu_data.get("bbu_type"))
                if bbu_data.get("temperature") is None and cv_fallback.get("temperature") is not None:
                    bbu_data["temperature"] = cv_fallback["temperature"]

    return controller_report


def _extract_policy_value(response: Dict[str, Any], policy_name: str) -> Optional[int]:
    """Extract a numeric policy value from the Policies Table.

    storcli7 stores policies in a list like:
        [{"Policy": "Rebuild Rate", "Current": "30 %", "Default": "30%"}, ...]

    Args:
        response: Full controller response data.
        policy_name: Exact policy name to search for.

    Returns:
        Integer value, or None if not found.
    """
    policies = response.get("Policies", {})
    if isinstance(policies, dict):
        # Check "Policies Table" list
        table = policies.get("Policies Table", [])
        if isinstance(table, list):
            for entry in table:
                if isinstance(entry, dict) and entry.get("Policy") == policy_name:
                    current = entry.get("Current", "")
                    return _safe_int(current) or None
        # Also check direct key under Policies
        direct = policies.get(policy_name)
        if direct is not None:
            return _safe_int(direct) or None
    return None


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
    bus = response.get("Bus", {})

    # Extract rebuild rate from Policies section
    rebuild_rate = _extract_policy_value(response, "Rebuild Rate")
    if rebuild_rate is None:
        # Fallback: top-level "Rebuild Rate" dict or value
        rb = response.get("Rebuild Rate")
        if isinstance(rb, dict):
            rebuild_rate = _safe_int(rb.get("Rebuild Rate"))
        elif rb is not None and str(rb).lower() != "yes":
            rebuild_rate = _safe_int(rb)

    # Extract CC rate from Policies section
    cc_rate = _extract_policy_value(response, "Check Consistency Rate")

    # Extract patrol read status
    patrol_read = ""
    pr_data = response.get("Patrol Read", {})
    if isinstance(pr_data, dict):
        patrol_read = pr_data.get("PR Mode", pr_data.get("Patrol Read Mode", ""))
    # Also check Scheduled Tasks
    sched = response.get("Scheduled Tasks", {})
    if isinstance(sched, dict):
        pr_reoccurrence = sched.get("Patrol Read Reoccurrence", "")
        if pr_reoccurrence and not patrol_read:
            patrol_read = f"Every {pr_reoccurrence}"
        elif pr_reoccurrence and patrol_read:
            patrol_read = f"{patrol_read} ({pr_reoccurrence})"

    return {
        "model": basics.get("Model", ""),
        "serial_number": basics.get("Serial Number", ""),
        "status": status.get("Controller Status", ""),
        "firmware_version": version.get("Firmware Version", ""),
        "bios_version": version.get("Bios Version", version.get("BIOS Version", "")),
        "driver_version": version.get("Driver Version", ""),
        "memory_size": hw_cfg.get("On Board Memory Size", ""),
        "memory_correctable_errors": _safe_int(status.get("Memory Correctable Errors", 0)),
        "memory_uncorrectable_errors": _safe_int(status.get("Memory Uncorrectable Errors", 0)),
        "roc_temperature": _safe_int(_parse_temperature(
            hw_cfg.get("ROC temperature(Degree Celsius)", "")
        )) or None,
        "alarm_status": hw_cfg.get("Alarm", ""),
        "patrol_read_status": patrol_read or None,
        "rebuild_rate": rebuild_rate if rebuild_rate else None,
        "cc_status": f"{cc_rate}%" if cc_rate else None,
        "host_interface": bus.get("Host Interface", hw_cfg.get("Host Interface", "")),
        "product_name": basics.get("Product Name", ""),
        "supported_raid_levels": _parse_supported_raids(response),
        # Scheduled tasks
        "next_cc_launch": sched.get("Next Consistency check launch", "") if isinstance(sched, dict) else "",
        "next_pr_launch": sched.get("Next Patrol Read launch", "") if isinstance(sched, dict) else "",
        "next_battery_learn": sched.get("Next Battery Learn", "") if isinstance(sched, dict) else "",
        # Additional status
        "ecc_bucket_count": _safe_int(status.get("ECC Bucket Count", 0)),
        # Additional version info
        "firmware_package_build": version.get("Firmware Package Build", ""),
        "driver_name": version.get("Driver Name", ""),
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
    # Handle format like "19C (66.20 F)" — split on "(" first
    if "(" in text:
        text = text.split("(")[0].strip()
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
    raid_levels = capabilities.get("RAID Level Supported", capabilities.get("Supported RAID Levels", ""))

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

    # storcli7 format: VDs are in keys like "/c0/v0", "/c0/v1" etc.
    if not vds_raw:
        for key, val in response.items():
            if key.startswith("/c") and "/v" in key and isinstance(val, list):
                vds_raw.extend(val)

    # Detailed VD info may be in separate keys like "VD0 Properties"
    vd_properties = {}
    for key, val in response.items():
        if "Properties" in key and key.startswith("VD"):
            try:
                vd_num = int("".join(filter(str.isdigit, key.split(" ")[0])))
                vd_properties[vd_num] = val if isinstance(val, dict) else {}
            except (ValueError, IndexError):
                pass

    # Also check "PDs for VD N" for drive count per VD
    vd_pd_counts = {}
    for key, val in response.items():
        if key.startswith("PDs for VD") and isinstance(val, list):
            try:
                vd_num = int(key.split("PDs for VD")[1].strip())
                vd_pd_counts[vd_num] = len(val)
            except (ValueError, IndexError):
                pass

    for idx, vd_raw in enumerate(vds_raw):
        vd = _parse_single_vd(vd_raw, idx, vd_properties.get(idx, {}))
        # Fix number_of_drives from actual PD count if available
        if vd["number_of_drives"] in (0, None):
            vd_id = vd.get("vd_id", idx)
            if vd_id in vd_pd_counts:
                vd["number_of_drives"] = vd_pd_counts[vd_id]
            elif idx in vd_pd_counts:
                vd["number_of_drives"] = vd_pd_counts[idx]
            else:
                # Try from properties "Number of Drives Per Span"
                props = vd_properties.get(vd_id, vd_properties.get(idx, {}))
                ndrives = props.get("Number of Drives Per Span", props.get("Number of Drives", None))
                if ndrives is not None:
                    vd["number_of_drives"] = _safe_int(ndrives)
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
        "number_of_drives": _safe_int(properties.get("Number of Drives Per Span",
            properties.get("Number of Drives", vd_raw.get("DGs", 0)))),
        "os_drive_name": str(properties.get("OS Drive Name", "")),
        "creation_date": str(properties.get("Creation Date", "")),
        "creation_time": str(properties.get("Creation Time", "")),
        "active_operations": str(properties.get("Active Operations", "")),
        "write_cache": str(properties.get("Write Cache(initial setting)", properties.get("Write Cache", ""))),
        "span_depth": _safe_int(properties.get("Span Depth", 0)),
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

    # PDs can be in several locations depending on storcli version
    pds_raw = response.get("PD LIST", response.get("Physical Drives", []))

    # storcli7 format: "Drive Information" key
    if not pds_raw:
        pds_raw = response.get("Drive Information", [])

    # storcli7 format: individual drive keys like "Drive /c0/e8/s0", "Drive /c0/e8/s1"
    # Each key is a list with 1 PD entry; collect ALL of them
    if not pds_raw:
        for key, val in response.items():
            if key.startswith(f"Drive /c{cx}/e") and "/s" in key and isinstance(val, list):
                if "Detailed Information" not in key:
                    pds_raw.extend(val)

    # Fallback: keys without "Drive " prefix — "/c0/e8/s0", "/c0/e8/s1"
    if not pds_raw:
        for key, val in response.items():
            if key.startswith(f"/c{cx}/e") and "/s" in key and isinstance(val, list):
                pds_raw.extend(val)

    # Also check "PDs for VD N" keys (from vall response passed as fallback)
    if not pds_raw:
        for key, val in response.items():
            if key.startswith("PDs for VD") and isinstance(val, list):
                pds_raw.extend(val)

    if not isinstance(pds_raw, list):
        pds_raw = []

    logger.debug("Found %d raw PD entries for /c%d", len(pds_raw), cx)

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
            link_speed = device_attrs.get("Link Speed", "")
            device_speed = device_attrs.get("Device Speed", "")
            physical_sector_size = device_attrs.get("Physical Sector Size", "")
            wwn = device_attrs.get("WWN", "")
        else:
            manufacturer = ""
            link_speed = ""
            device_speed = ""
            physical_sector_size = ""
            wwn = ""

        # State attributes
        state_key = f"Drive /c{cx}/e{enclosure}/s{slot} State"
        state_attrs = detailed.get(state_key, {})
        if isinstance(state_attrs, dict):
            temp_raw = _parse_temperature(
                state_attrs.get("Drive Temperature", "")
            )
            temperature = int(temp_raw) if temp_raw is not None else None
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

    result = {
        "enclosure_id": enclosure,
        "slot_number": slot,
        "state": str(state),
        "media_type": str(media_type),
        "interface_type": str(interface),
        "size": str(size),
        "model": str(model).strip(),
        "serial_number": str(serial).strip(),
        "firmware_version": str(firmware).strip(),
        "manufacturer": str(manufacturer).strip() if manufacturer else "",
        "temperature": temperature,
        "drive_group": _safe_int(pd_raw.get("DG", pd_raw.get("Disk Group", -1))),
        "span": _safe_int(pd_raw.get("Sp", -1)),
        "device_id": _safe_int(pd_raw.get("DID", pd_raw.get("Device Id", -1))),
        "sector_size": str(pd_raw.get("SeSz", pd_raw.get("Sector Size", ""))),
        "link_speed": str(link_speed).strip(),
        "device_speed": str(device_speed).strip(),
        "physical_sector_size": str(physical_sector_size).strip(),
        "wwn": str(wwn).strip(),
        "smart_data": smart_attributes,
    }

    # Flatten SMART attributes to top level for agent_processor compatibility
    if smart_attributes:
        result["media_error_count"] = smart_attributes.get("media_error_count", 0)
        result["other_error_count"] = smart_attributes.get("other_error_count", 0)
        result["predictive_failure"] = smart_attributes.get("predictive_failure_count", 0)
        result["shield_counter"] = smart_attributes.get("shield_counter", 0)
        smart_alert_str = str(smart_attributes.get("smart_alert", "No")).lower()
        result["smart_alert"] = smart_alert_str not in ("no", "false", "0", "")

    return result


def _parse_cachevault_from_controller(response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract CacheVault info from controller 'show all' response.

    storcli7 includes Cachevault_Info in the controller show all output:
        "Cachevault_Info": [{"Model": "CVPM02", "State": "Optimal", "Temp": "23C", ...}]

    This is used as fallback when /cx/bbu and /cx/cv commands both fail.
    """
    cv_info = response.get("Cachevault_Info", [])
    if not cv_info:
        return None

    if isinstance(cv_info, list) and cv_info:
        cv_entry = cv_info[0]
    elif isinstance(cv_info, dict):
        cv_entry = cv_info
    else:
        return None

    if not isinstance(cv_entry, dict):
        return None

    model = cv_entry.get("Model", "")
    state = cv_entry.get("State", "")
    temp = _parse_temperature(cv_entry.get("Temp", ""))
    mfg_date = cv_entry.get("MfgDate", "")

    return {
        "type": "CV",
        "bbu_type": model or "CacheVault",
        "present": True,
        "state": str(state),
        "temperature": int(temp) if temp is not None else None,
        "manufacture_date": str(mfg_date),
        "replacement_needed": state.lower() not in ("optimal", "opt", "ready", ""),
        # Extended fields from controller show all are limited
        "capacitance": "",
        "pack_energy": "",
        "flash_size": str(cv_entry.get("WriteSize", "")),
    }


def _resolve_relative_event_times(events: List[Dict[str, Any]]) -> None:
    """Compute approximate timestamps for events with only relative time.

    Early boot events from storcli only have "Seconds since last reboot"
    instead of absolute timestamps. This function computes approximate
    absolute times using system uptime from /proc/uptime.

    Events with absolute time are left unchanged. The internal
    _seconds_since_reboot field is removed after processing.
    """
    from datetime import datetime, timedelta

    # Check if any events need timestamp resolution
    need_resolution = [e for e in events if "_seconds_since_reboot" in e]
    if not need_resolution:
        return

    # Try to compute boot time from system uptime
    boot_time = None
    try:
        with open("/proc/uptime", "r") as f:
            uptime_secs = float(f.read().split()[0])
        boot_time = datetime.now() - timedelta(seconds=uptime_secs)
    except Exception:
        logger.debug("Cannot read /proc/uptime for event time resolution")

    # Alternative: find a reference event that has both absolute time and
    # is close in sequence to relative-time events
    if boot_time is None:
        for evt in events:
            if evt.get("event_time") and "_seconds_since_reboot" not in evt:
                # Can't compute boot_time without uptime; skip
                break

    for evt in events:
        secs = evt.pop("_seconds_since_reboot", None)
        if secs is not None and not evt.get("event_time") and boot_time is not None:
            approx_time = boot_time + timedelta(seconds=secs)
            evt["event_time"] = approx_time.strftime("%Y-%m-%dT%H:%M:%S")

    resolved = sum(1 for e in need_resolution if e.get("event_time"))
    logger.debug("Resolved %d/%d relative event timestamps", resolved, len(need_resolution))


_EVENT_CLASS_MAP = {
    "-1": "progress",
    "0": "info",
    "1": "warning",
    "2": "critical",
    "3": "fatal",
}


def _map_event_severity(class_val: str) -> str:
    """Map storcli event Class value to severity string."""
    return _EVENT_CLASS_MAP.get(str(class_val).strip(), "info")


def parse_events(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse controller events from storcli JSON 'show events' response.

    Field names match agent_processor._record_events expectations:
    event_id, event_time, severity, event_class, event_description, event_data.
    """
    events = []

    raw_events = response.get("Controller Event Log Entries", [])

    if not isinstance(raw_events, list):
        if isinstance(raw_events, dict):
            raw_events = list(raw_events.values())
        else:
            return events

    for evt_raw in raw_events:
        if not isinstance(evt_raw, dict):
            continue

        class_val = str(evt_raw.get("Class", evt_raw.get("Severity", "0")))
        event = {
            "event_id": _safe_int(evt_raw.get("Seq Num", evt_raw.get("SeqNum", 0))),
            "event_time": str(evt_raw.get("Time Stamp", evt_raw.get("TimeStamp", ""))),
            "severity": _map_event_severity(class_val),
            "event_class": class_val,
            "event_description": str(evt_raw.get("Event Description", evt_raw.get("Description", ""))),
            "event_data": evt_raw.get("Event Data"),
        }
        events.append(event)

    logger.debug("Parsed %d JSON events", len(events))
    return events


def parse_events_text(text: str) -> List[Dict[str, Any]]:
    """Parse controller events from storcli TEXT output.

    Text format:
        seqNum: 0x00007093
        Time: Tue Feb 24 00:05:05 2026
        Code: 0x0000009d
        Class: 0
        Locale: 0x08
        Event Description: Battery relearn will start in 4 days
        Event Data:
        ===========
        None

    Returns:
        List of event dicts matching agent_processor field names.
    """
    import re
    from datetime import datetime as _dt

    events = []
    current: Dict[str, Any] = {}
    in_event_data = False
    event_data_lines: List[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        # New event block
        if stripped.startswith("seqNum:"):
            # Save previous event
            if current:
                _finalize_text_event(current, event_data_lines, events)
            current = {}
            event_data_lines = []
            in_event_data = False
            seq_hex = stripped.split(":", 1)[1].strip()
            try:
                current["event_id"] = int(seq_hex, 16) if seq_hex.startswith("0x") else int(seq_hex)
            except ValueError:
                current["event_id"] = 0
            continue

        if not current:
            continue

        # Collect event data lines first (before field checks) to avoid
        # misinterpreting "Time:" or "Code:" inside Event Data blocks
        if in_event_data:
            if stripped.startswith("====="):
                continue
            if not stripped:
                continue
            if stripped.startswith("CLI Version") or stripped.startswith("Controller Properties"):
                in_event_data = False
                continue
            event_data_lines.append(stripped)
            continue

        if stripped.startswith("Time:"):
            time_str = stripped.split(":", 1)[1].strip()
            current["event_time"] = _parse_event_time(time_str)
            continue

        if stripped.startswith("Seconds since last reboot:"):
            secs_str = stripped.split(":", 1)[1].strip()
            try:
                current["_seconds_since_reboot"] = int(secs_str)
            except ValueError:
                pass
            continue

        if stripped.startswith("Code:"):
            current["event_code"] = stripped.split(":", 1)[1].strip()
            continue

        if stripped.startswith("Class:"):
            class_val = stripped.split(":", 1)[1].strip()
            current["event_class"] = class_val
            current["severity"] = _map_event_severity(class_val)
            continue

        if stripped.startswith("Locale:"):
            continue

        if stripped.startswith("Event Description:"):
            current["event_description"] = stripped.split(":", 1)[1].strip()
            continue

        if stripped == "Event Data:":
            in_event_data = True
            continue

        if stripped.startswith("====="):
            continue

    # Save last event
    if current:
        _finalize_text_event(current, event_data_lines, events)

    logger.debug("Parsed %d text events", len(events))
    return events


def _finalize_text_event(
    current: Dict[str, Any],
    event_data_lines: List[str],
    events: List[Dict[str, Any]],
) -> None:
    """Finalize a text-parsed event and add to events list."""
    data_text = "\n".join(event_data_lines).strip()
    if data_text.lower() == "none" or not data_text:
        data_text = None

    event = {
        "event_id": current.get("event_id", 0),
        "event_time": current.get("event_time"),
        "severity": current.get("severity", "info"),
        "event_class": current.get("event_class", "0"),
        "event_description": current.get("event_description", ""),
        "event_data": {"text": data_text} if data_text else None,
    }
    # Preserve relative timestamp for later resolution
    if "_seconds_since_reboot" in current:
        event["_seconds_since_reboot"] = current["_seconds_since_reboot"]
    events.append(event)


def _parse_event_time(time_str: str) -> Optional[str]:
    """Parse storcli event timestamp string to ISO format.

    Input: 'Tue Feb 24 00:05:05 2026'
    Output: '2026-02-24T00:05:05'
    """
    from datetime import datetime as _dt

    formats = [
        "%a %b %d %H:%M:%S %Y",   # Tue Feb 24 00:05:05 2026
        "%m/%d/%Y, %H:%M:%S",     # 02/24/2026, 00:05:05
    ]
    for fmt in formats:
        try:
            dt = _dt.strptime(time_str.strip(), fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return time_str


def _prop_value_list_to_dict(data) -> Dict[str, str]:
    """Convert a list of {"Property": ..., "Value": ...} dicts to a flat dict.

    storcli7 /cx/cv show all J returns data in this format instead of
    regular key-value dicts.
    """
    if isinstance(data, dict):
        return data
    if not isinstance(data, list):
        return {}
    result = {}
    for item in data:
        if isinstance(item, dict) and "Property" in item and "Value" in item:
            result[item["Property"]] = item["Value"]
    return result


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

        result["bbu_type"] = "BBU"

        if isinstance(bbu_status, dict):
            temp = _parse_temperature(bbu_status.get("Temperature", ""))
            voltage_mv = _safe_float(bbu_status.get("Voltage", ""))
            result.update({
                "temperature": int(temp) if temp is not None else None,
                "state": str(bbu_status.get("Battery State", "")),
                "voltage": f"{voltage_mv} mV" if voltage_mv else None,
                "learn_cycle_status": str(bbu_status.get("Learn Cycle Active", "")),
            })

        if isinstance(bbu_capacity, dict):
            remaining = _safe_int(bbu_capacity.get("Remaining Capacity", 0))
            full_charge = _safe_int(bbu_capacity.get("Full Charge Capacity", 0))
            relative_pct = _safe_int(bbu_capacity.get("Relative State of Charge", 0))
            if relative_pct:
                result["remaining_capacity"] = f"{relative_pct}%"
            elif remaining and full_charge:
                result["remaining_capacity"] = f"{remaining}/{full_charge} mAh"
            elif remaining:
                result["remaining_capacity"] = f"{remaining} mAh"

        if isinstance(bbu_firmware, dict):
            repl = str(bbu_firmware.get("Battery Replacement required", "No"))
            result["replacement_needed"] = repl.lower() in ("yes", "true", "1")

    elif source == "cv":
        # CacheVault data parsing
        # /cx/cv show all J returns arrays of {"Property": ..., "Value": ...}
        # Convert them to dicts for easier access
        cv_info_raw = response.get("Cachevault_Info", [])
        cv_firmware_raw = response.get("Firmware_Status", [])
        cv_gasgauge_raw = response.get("GasGaugeStatus", [])
        cv_design_raw = response.get("Design_Info", [])

        cv_info = _prop_value_list_to_dict(cv_info_raw)
        cv_firmware = _prop_value_list_to_dict(cv_firmware_raw)
        cv_gasgauge = _prop_value_list_to_dict(cv_gasgauge_raw)
        cv_design = _prop_value_list_to_dict(cv_design_raw)

        if cv_info:
            temp = _parse_temperature(cv_info.get("Temp", cv_info.get("Temperature", "")))
            model = cv_info.get("Type", cv_info.get("Model", ""))
            result.update({
                "bbu_type": model or "CacheVault",
                "temperature": int(temp) if temp is not None else None,
                "state": str(cv_info.get("State", "")),
                "replacement_needed": str(cv_info.get("Replacement required", "No")).lower() in ("yes", "true", "1"),
            })

        if cv_firmware:
            health = str(cv_firmware.get("Health", ""))
            if health and not result.get("state"):
                result["state"] = health

        # CacheVault extended info
        if cv_gasgauge:
            result["capacitance"] = str(cv_gasgauge.get("Capacitance", ""))
            result["pack_energy"] = str(cv_gasgauge.get("Pack Energy", ""))

        if cv_design:
            result["manufacture_date"] = str(cv_design.get("Date of Manufacture", ""))
            result["flash_size"] = str(cv_design.get("CacheVault Flash Size", ""))

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
    if isinstance(value, (int, float)):
        return int(value)
    try:
        # Handle strings like "123 MB" or "60.0" by taking the first numeric part
        text = str(value).strip().split()[0] if str(value).strip() else ""
        return int(float(text))
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
