"""Software RAID (mdadm) and SMART data collector for the RAID Monitor Agent.

Detects Linux software RAID arrays via /proc/mdstat and mdadm,
collects S.M.A.R.T. data from all block devices via smartctl,
and returns structured reports for the central server.
"""

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SMARTCTL_TIMEOUT = 30
MDADM_TIMEOUT = 15


# ---------------------------------------------------------------------------
# smartctl helpers
# ---------------------------------------------------------------------------

def get_smartctl_version(smartctl_path: str) -> str:
    """Get smartctl version string.

    Args:
        smartctl_path: Full path to smartctl binary.

    Returns:
        Version string (e.g. "7.3"), or empty string on failure.
    """
    if not smartctl_path:
        return ""
    try:
        result = subprocess.run(
            [smartctl_path, "--version"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        for line in result.stdout.splitlines():
            if "smartctl" in line.lower():
                # "smartctl 7.3 2022-02-28 ..."
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.lower() == "smartctl" and i + 1 < len(parts):
                        return parts[i + 1]
        return ""
    except Exception:
        return ""


def _run_smartctl(smartctl_path: str, args: List[str]) -> Dict[str, Any]:
    """Run smartctl with --json flag and return parsed JSON.

    smartctl exit codes use a bitmask — non-zero does NOT always mean failure.
    Bits 0-1 are errors, bits 2-7 are disk status warnings.
    We consider the output valid if we can parse JSON from stdout.
    """
    cmd = [smartctl_path] + args
    logger.debug("Executing: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=SMARTCTL_TIMEOUT, check=False,
        )
    except FileNotFoundError:
        logger.error("smartctl binary not found: %s", smartctl_path)
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("smartctl timed out: %s", " ".join(cmd))
        return {}

    # Try to parse JSON even with non-zero exit codes
    stdout = result.stdout.strip()
    if not stdout:
        if result.returncode & 0x03:
            logger.debug("smartctl error (exit %d): %s", result.returncode, result.stderr.strip()[:200])
        return {}

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        logger.debug("smartctl output is not JSON (exit %d)", result.returncode)
        return {}


def scan_drives(smartctl_path: str) -> List[Dict[str, str]]:
    """Discover all block devices via smartctl --scan.

    Returns:
        List of dicts with 'device' and 'type' keys.
    """
    data = _run_smartctl(smartctl_path, ["--scan", "--json"])
    devices = data.get("devices", [])

    result = []
    for dev in devices:
        name = dev.get("name", "")
        dev_type = dev.get("type", "")
        if name:
            result.append({"device": name, "type": dev_type})

    logger.debug("smartctl --scan found %d devices", len(result))
    return result


def _extract_smart_attr(attrs: List[Dict], attr_id: int) -> Optional[int]:
    """Extract raw value for a specific SMART attribute by ID."""
    for attr in attrs:
        if attr.get("id") == attr_id:
            raw = attr.get("raw", {})
            if isinstance(raw, dict):
                return raw.get("value")
            return raw
    return None


def collect_drive_smart(smartctl_path: str, device: str, dev_type: str = "", scan_type: str = "") -> Optional[Dict[str, Any]]:
    """Collect full SMART data for a single drive.

    Args:
        smartctl_path: Path to smartctl binary.
        device: Device path (e.g. /dev/sda).
        dev_type: Device type hint (e.g. "sat", "nvme").
        scan_type: Raw type string from smartctl --scan (e.g. "megaraid,0").

    Returns:
        Structured dict with SMART data, or None on failure.
    """
    args = ["-a", "--json", device]
    if dev_type:
        args = ["-a", "--json", "-d", dev_type, device]

    data = _run_smartctl(smartctl_path, args)
    if not data:
        return None

    # Extract device info
    dev_info = data.get("device", {})
    model_info = data.get("model_family", "")
    model_name = data.get("model_name", "")
    serial = data.get("serial_number", "")
    firmware = data.get("firmware_version", "")
    rotation = data.get("rotation_rate", 0)

    # Determine device type
    protocol = dev_info.get("protocol", "").upper()
    if protocol == "NVME":
        device_type = "NVMe"
    elif rotation == 0:
        device_type = "SSD"
    else:
        device_type = "HDD"

    # Capacity
    capacity_bytes = data.get("user_capacity", {}).get("bytes", 0)
    if capacity_bytes:
        gb = capacity_bytes / (1024 ** 3)
        if gb >= 1000:
            capacity = f"{gb / 1024:.2f} TB"
        else:
            capacity = f"{gb:.1f} GB"
    else:
        capacity = None

    # SMART overall status
    smart_status_obj = data.get("smart_status", {})
    smart_passed = smart_status_obj.get("passed")

    # Temperature
    temperature = None
    temp_obj = data.get("temperature", {})
    if isinstance(temp_obj, dict):
        temperature = temp_obj.get("current")

    # Power-on hours
    power_on = data.get("power_on_time", {})
    power_on_hours = None
    if isinstance(power_on, dict):
        power_on_hours = power_on.get("hours")

    # ATA SMART attributes
    ata_attrs = data.get("ata_smart_attributes", {}).get("table", [])

    reallocated = _extract_smart_attr(ata_attrs, 5)
    pending = _extract_smart_attr(ata_attrs, 197)
    uncorrectable = _extract_smart_attr(ata_attrs, 198)

    # NVMe health (alternative path)
    nvme_health = data.get("nvme_smart_health_information_log", {})
    if protocol == "NVME" and nvme_health:
        if temperature is None:
            temperature = nvme_health.get("temperature")
        if power_on_hours is None:
            power_on_hours = nvme_health.get("power_on_hours")

    # Build attribute list for UI
    smart_attributes = []
    for attr in ata_attrs:
        smart_attributes.append({
            "id": attr.get("id"),
            "name": attr.get("name", ""),
            "value": attr.get("value"),
            "worst": attr.get("worst"),
            "thresh": attr.get("thresh"),
            "type": attr.get("type", {}).get("string", "") if isinstance(attr.get("type"), dict) else "",
            "updated": attr.get("updated", {}).get("string", "") if isinstance(attr.get("updated"), dict) else "",
            "when_failed": attr.get("when_failed", {}).get("string", "") if isinstance(attr.get("when_failed"), dict) else str(attr.get("when_failed", "")),
            "raw_value": attr.get("raw", {}).get("string", "") if isinstance(attr.get("raw"), dict) else str(attr.get("raw", "")),
        })

    return {
        "device": device,
        "scan_type": scan_type,
        "model": model_name or model_info,
        "serial_number": serial,
        "firmware_version": firmware,
        "device_type": device_type,
        "capacity": capacity,
        "smart_status": smart_passed,
        "temperature": temperature,
        "power_on_hours": power_on_hours,
        "reallocated_sectors": reallocated,
        "pending_sectors": pending,
        "uncorrectable_sectors": uncorrectable,
        "smart_attributes": smart_attributes if smart_attributes else None,
        "smart_data": data,
    }


def collect_all_smart(smartctl_path: str) -> List[Dict[str, Any]]:
    """Scan all drives and collect SMART data for each.

    Args:
        smartctl_path: Path to smartctl binary.

    Returns:
        List of drive SMART reports.
    """
    if not smartctl_path:
        return []

    drives = scan_drives(smartctl_path)
    results = []
    for drv in drives:
        try:
            report = collect_drive_smart(smartctl_path, drv["device"], drv.get("type", ""), scan_type=drv.get("type", ""))
            if report:
                results.append(report)
        except Exception:
            logger.warning("Failed to collect SMART for %s", drv["device"], exc_info=True)

    logger.info("Collected SMART data for %d/%d drives", len(results), len(drives))
    return results


# ---------------------------------------------------------------------------
# mdadm / software RAID helpers
# ---------------------------------------------------------------------------

def _parse_mdstat() -> List[Dict[str, Any]]:
    """Parse /proc/mdstat to discover active software RAID arrays.

    Returns:
        List of dicts with basic array info (name, level, state, members).
    """
    mdstat_path = "/proc/mdstat"
    if not os.path.isfile(mdstat_path):
        logger.debug("/proc/mdstat not found — no software RAID")
        return []

    try:
        with open(mdstat_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as exc:
        logger.warning("Failed to read /proc/mdstat: %s", exc)
        return []

    arrays = []
    current = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("Personalities") or line.startswith("unused"):
            continue

        # Array header: "md0 : active raid1 sda1[0] sdb1[1]"
        m = re.match(r'^(md\S+)\s*:\s*(\w+)\s+(\w+)\s+(.*)', line)
        if m:
            if current:
                arrays.append(current)
            md_name = m.group(1)
            activity = m.group(2)  # active / inactive
            raid_level = m.group(3)  # raid1, raid5, ...
            members_str = m.group(4)

            # Parse member devices: "sda1[0] sdb1[1](F) sdc1[2](S)"
            members = []
            for mem_match in re.finditer(r'(\S+?)\[(\d+)\](\([A-Z]+\))?', members_str):
                dev = mem_match.group(1)
                role_num = mem_match.group(2)
                flags = mem_match.group(3) or ""
                state = "in_sync"
                role = "active"
                if "(F)" in flags:
                    state = "faulty"
                    role = "faulty"
                elif "(S)" in flags:
                    state = "spare"
                    role = "spare"
                members.append({
                    "device": f"/dev/{dev}",
                    "role": role,
                    "state": state,
                })

            current = {
                "array_name": f"/dev/{md_name}",
                "raid_level": raid_level,
                "state": activity,
                "member_devices": members,
            }
            continue

        # Status line: "123456 blocks super 1.2 [2/2] [UU]"
        if current and "[" in line and "]" in line:
            # Extract [UU] or [U_] state
            uu_match = re.search(r'\[([U_]+)\]', line)
            if uu_match:
                uu_str = uu_match.group(1)
                total = len(uu_str)
                up = uu_str.count("U")
                down = total - up
                current["num_devices"] = total
                current["active_devices"] = up
                current["failed_devices"] = down
                if down > 0:
                    current["state"] = "degraded"
                elif current["state"] == "active":
                    current["state"] = "active"

            # Extract size
            blocks_match = re.match(r'(\d+)\s+blocks', line)
            if blocks_match:
                blocks = int(blocks_match.group(1))
                size_gb = blocks / (1024 * 1024)
                if size_gb >= 1024:
                    current["array_size"] = f"{size_gb / 1024:.2f} TB"
                else:
                    current["array_size"] = f"{size_gb:.1f} GB"

        # Rebuild line: "[====>................]  recovery = 25.0% (123/456) finish=1.2min speed=123K/sec"
        if current and ("recovery" in line or "resync" in line or "reshape" in line):
            progress_match = re.search(r'=\s*([\d.]+)%', line)
            if progress_match:
                current["rebuild_progress"] = float(progress_match.group(1))
                current["state"] = "rebuilding"

    if current:
        arrays.append(current)

    logger.debug("Parsed %d arrays from /proc/mdstat", len(arrays))
    return arrays


def _get_mdadm_detail(array_name: str) -> Dict[str, Any]:
    """Get detailed info for an mdadm array via 'mdadm --detail'.

    Args:
        array_name: Array device path (e.g. /dev/md0).

    Returns:
        Dict with additional detail fields, or empty dict on failure.
    """
    mdadm_path = shutil.which("mdadm")
    if not mdadm_path:
        return {}

    try:
        result = subprocess.run(
            [mdadm_path, "--detail", array_name],
            capture_output=True, text=True,
            timeout=MDADM_TIMEOUT, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    if result.returncode != 0:
        return {}

    detail = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "uuid":
            detail["uuid"] = value
        elif key == "creation time":
            detail["creation_time"] = value
        elif key == "raid level":
            detail["raid_level"] = value
        elif key == "array size":
            detail["array_size"] = value
        elif key == "state":
            detail["state"] = value.lower().replace(",", "").strip()
        elif key == "active devices":
            detail["active_devices"] = _safe_int(value)
        elif key == "working devices":
            detail["working_devices"] = _safe_int(value)
        elif key == "failed devices":
            detail["failed_devices"] = _safe_int(value)
        elif key == "spare devices":
            detail["spare_devices"] = _safe_int(value)
        elif key == "total devices":
            detail["num_devices"] = _safe_int(value)
        elif key == "rebuild status":
            pct_match = re.search(r'([\d.]+)%', value)
            if pct_match:
                detail["rebuild_progress"] = float(pct_match.group(1))
                detail["state"] = "rebuilding"

    return detail


def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def detect_software_raids() -> List[Dict[str, Any]]:
    """Detect all Linux software RAID arrays.

    Combines /proc/mdstat parsing with mdadm --detail enrichment.

    Returns:
        List of software RAID array reports.
    """
    arrays = _parse_mdstat()

    for arr in arrays:
        detail = _get_mdadm_detail(arr["array_name"])
        if detail:
            # Merge detail into array, preferring mdadm --detail values
            for key in ("uuid", "creation_time", "working_devices",
                        "spare_devices", "num_devices", "array_size"):
                if key in detail and detail[key] is not None:
                    arr[key] = detail[key]
            # State and rebuild from mdadm override mdstat
            if "state" in detail:
                arr["state"] = detail["state"]
            if "rebuild_progress" in detail:
                arr["rebuild_progress"] = detail["rebuild_progress"]
            if detail.get("active_devices") is not None:
                arr["active_devices"] = detail["active_devices"]
            if detail.get("failed_devices") is not None:
                arr["failed_devices"] = detail["failed_devices"]

    logger.info("Detected %d software RAID arrays", len(arrays))
    return arrays


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def collect_software_raid(smartctl_path: str = "") -> Dict[str, Any]:
    """Collect all software RAID and SMART data.

    Args:
        smartctl_path: Path to smartctl binary (empty if unavailable).

    Returns:
        Dict with 'software_raid_arrays' and 'smart_drives' keys.
    """
    sw_raids = []
    smart_drives = []

    try:
        sw_raids = detect_software_raids()
    except Exception:
        logger.warning("Software RAID detection failed", exc_info=True)

    try:
        smart_drives = collect_all_smart(smartctl_path)
    except Exception:
        logger.warning("SMART data collection failed", exc_info=True)

    return {
        "software_raid_arrays": sw_raids,
        "smart_drives": smart_drives,
    }
