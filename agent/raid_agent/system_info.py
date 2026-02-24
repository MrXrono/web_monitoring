"""System information collector for the RAID Monitor Agent.

Gathers host-level metadata including hostname, IP addresses, OS version,
CPU/RAM specs, uptime, and last OS update timestamp.
"""

import logging
import os
import platform
import re
import socket
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def get_system_info() -> Dict[str, Any]:
    """Collect comprehensive system information.

    Returns:
        Dict containing:
            hostname, fqdn, ip_address, os_name, os_version,
            kernel, cpu_model, cpu_cores, ram_total_gb,
            uptime_seconds, last_os_update.
    """
    info = {
        "hostname": _get_hostname(),
        "fqdn": _get_fqdn(),
        "ip_address": _get_primary_ip(),
        "os_name": "",
        "os_version": "",
        "kernel": platform.release(),
        "cpu_model": _get_cpu_model(),
        "cpu_cores": os.cpu_count() or 0,
        "ram_total_gb": _get_ram_total_gb(),
        "uptime_seconds": _get_uptime_seconds(),
        "last_os_update": _get_last_os_update(),
    }

    os_info = _parse_os_release()
    info["os_name"] = os_info.get("NAME", "")
    info["os_version"] = os_info.get("VERSION_ID", os_info.get("VERSION", ""))

    return info


def _get_hostname() -> str:
    """Get the short hostname.

    Returns:
        Hostname string.
    """
    try:
        return socket.gethostname()
    except Exception as exc:
        logger.warning("Failed to get hostname: %s", exc)
        return "unknown"


def _get_fqdn() -> str:
    """Get the fully qualified domain name.

    Returns:
        FQDN string.
    """
    try:
        return socket.getfqdn()
    except Exception as exc:
        logger.warning("Failed to get FQDN: %s", exc)
        return _get_hostname()


def _get_primary_ip() -> str:
    """Get the primary non-loopback IP address.

    Uses a UDP socket trick to determine the default route interface IP
    without actually sending any packets.

    Returns:
        IP address string, or empty string on failure.
    """
    try:
        # Create a UDP socket and connect to an external address
        # This determines the local IP used for the default route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            if ip and ip != "127.0.0.1":
                return ip
    except Exception:
        pass

    # Fallback: try to resolve hostname
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass

    # Last resort: enumerate network interfaces via /proc/net/fib_trie
    try:
        return _get_ip_from_proc()
    except Exception as exc:
        logger.warning("Failed to determine primary IP: %s", exc)
        return ""


def _get_ip_from_proc() -> str:
    """Extract primary IP from /proc/net/fib_trie as a fallback.

    Returns:
        IP address string, or empty string.
    """
    try:
        with open("/proc/net/fib_trie", "r", encoding="utf-8") as fh:
            content = fh.read()
        # Find LOCAL entries which are host IPs
        ips = re.findall(r"/32 host LOCAL\n\s+\|-- ([\d.]+)", content)
        for ip in ips:
            if ip != "127.0.0.1" and not ip.startswith("127."):
                return ip
    except (OSError, IOError):
        pass
    return ""


def _parse_os_release() -> Dict[str, str]:
    """Parse /etc/os-release for OS name and version.

    Returns:
        Dict of key-value pairs from the os-release file.
    """
    result = {}
    os_release_paths = ["/etc/os-release", "/usr/lib/os-release"]

    for path in os_release_paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if "=" not in line or line.startswith("#"):
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    result[key] = value
            break
        except (OSError, IOError):
            continue

    if not result:
        logger.debug("Could not read /etc/os-release")

    return result


def _get_cpu_model() -> str:
    """Extract CPU model name from /proc/cpuinfo.

    Returns:
        CPU model string, or empty string on failure.
    """
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    _, _, model = line.partition(":")
                    return model.strip()
    except (OSError, IOError) as exc:
        logger.debug("Failed to read /proc/cpuinfo: %s", exc)

    # Fallback for non-x86 architectures
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("hardware") or line.lower().startswith("cpu"):
                    _, _, model = line.partition(":")
                    model = model.strip()
                    if model:
                        return model
    except (OSError, IOError):
        pass

    return platform.processor() or ""


def _get_ram_total_gb() -> float:
    """Get total RAM in gigabytes from /proc/meminfo.

    Returns:
        RAM total in GB rounded to 2 decimal places, or 0.0 on failure.
    """
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    # Format: "MemTotal:       16384000 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        kb = int(parts[1])
                        return round(kb / (1024 * 1024), 2)
    except (OSError, IOError, ValueError) as exc:
        logger.debug("Failed to read /proc/meminfo: %s", exc)

    return 0.0


def _get_uptime_seconds() -> float:
    """Get system uptime in seconds from /proc/uptime.

    Returns:
        Uptime in seconds, or 0.0 on failure.
    """
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            line = fh.readline().strip()
            parts = line.split()
            if parts:
                return float(parts[0])
    except (OSError, IOError, ValueError) as exc:
        logger.debug("Failed to read /proc/uptime: %s", exc)

    return 0.0


def _get_last_os_update() -> Optional[str]:
    """Determine the timestamp of the last OS package update.

    Tries multiple methods in order:
        1. `rpm -qa --last | head -1` (RPM-based systems)
        2. stat /var/lib/dnf/history/ (DNF-based systems)
        3. stat /var/lib/yum/history/ (YUM-based systems)

    Returns:
        ISO-formatted date string, or None if undetermined.
    """
    # Method 1: rpm query
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--last"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            first_line = result.stdout.strip().split("\n")[0]
            # Format: "package-name   Mon 01 Jan 2024 12:00:00 AM UTC"
            # The date starts after the package name, typically after multiple spaces
            parts = re.split(r"\s{2,}", first_line, maxsplit=1)
            if len(parts) >= 2:
                return parts[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Method 2: DNF history directory mtime
    try:
        dnf_history = "/var/lib/dnf/history/"
        if os.path.isdir(dnf_history):
            mtime = os.stat(dnf_history).st_mtime
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            return dt.isoformat()
    except (OSError, ValueError):
        pass

    # Method 3: YUM history directory mtime
    try:
        yum_history = "/var/lib/yum/history/"
        if os.path.isdir(yum_history):
            mtime = os.stat(yum_history).st_mtime
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            return dt.isoformat()
    except (OSError, ValueError):
        pass

    logger.debug("Could not determine last OS update timestamp")
    return None
