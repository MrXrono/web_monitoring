"""HTTPS reporter for the RAID Monitor Agent.

Handles all communication with the central RAID Monitor server:
registration, report submission, command fetching, log upload,
and configuration retrieval. All requests use bearer token auth,
configurable SSL verification, and retry logic with exponential backoff.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional, Union

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from raid_agent import __version__

logger = logging.getLogger(__name__)

# Default request timeout in seconds
REQUEST_TIMEOUT = 30

# Retry configuration for 5xx errors
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.0  # 1s, 2s, 4s
RETRY_STATUS_CODES = (500, 502, 503, 504)


def _build_session(
    api_key: str = "",
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> requests.Session:
    """Build a configured requests session with retry logic and auth headers.

    Args:
        api_key: Bearer token for authentication.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle file.

    Returns:
        Configured requests.Session instance.
    """
    session = requests.Session()

    # Setup retry strategy with exponential backoff on 5xx
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods=["GET", "POST", "PUT"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Set headers
    session.headers.update({
        "User-Agent": f"raid-agent/{__version__}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })

    if api_key:
        session.headers["Authorization"] = f"Bearer {api_key}"

    # SSL verification
    if ca_bundle and os.path.isfile(ca_bundle):
        session.verify = ca_bundle
    else:
        session.verify = ssl_verify

    # Suppress InsecureRequestWarning when SSL verification is disabled
    if not session.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session


def _build_url(server_url: str, path: str) -> str:
    """Build full API URL from server base URL and path.

    Args:
        server_url: Base server URL (e.g., https://raid-monitor.example.com).
        path: API path (e.g., /api/v1/agent/register).

    Returns:
        Full URL string.
    """
    return f"{server_url.rstrip('/')}{path}"


def register(
    server_url: str,
    hostname: str,
    ip: str,
    os_info: Dict[str, str],
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> str:
    """Register this agent with the central server.

    Sends system identification data and receives an API key for
    subsequent authenticated requests.

    Args:
        server_url: Base server URL.
        hostname: Agent hostname.
        ip: Agent primary IP address.
        os_info: Dict with os_name, os_version, kernel, fqdn.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        API key string on success.

    Raises:
        RuntimeError: If registration fails.
        requests.RequestException: On network errors after retries.
    """
    url = _build_url(server_url, "/api/v1/agent/register")
    payload = {
        "hostname": hostname,
        "ip_address": ip,
        "os_name": os_info.get("os_name", ""),
        "os_version": os_info.get("os_version", ""),
        "kernel": os_info.get("kernel", ""),
        "fqdn": os_info.get("fqdn", ""),
        "agent_version": __version__,
    }

    session = _build_session(ssl_verify=ssl_verify, ca_bundle=ca_bundle)
    logger.info("Registering with server: POST %s", url)

    try:
        response = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Registration request failed: %s", exc)
        raise

    if response.status_code not in (200, 201):
        error_msg = _extract_error(response)
        logger.error(
            "Registration failed: HTTP %d - %s", response.status_code, error_msg
        )
        raise RuntimeError(
            f"Registration failed: HTTP {response.status_code} - {error_msg}"
        )

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("Server returned non-JSON response during registration")

    api_key = data.get("api_key", data.get("token", ""))
    if not api_key:
        raise RuntimeError("Server did not return an API key in registration response")

    logger.info("Registration successful, received API key")
    return api_key


def send_report(
    server_url: str,
    api_key: str,
    report: Dict[str, Any],
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> bool:
    """Send a RAID data report to the server.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        report: Full report dict (controllers, system_info, etc.).
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        True if report was accepted (2xx), False otherwise.
    """
    url = _build_url(server_url, "/api/v1/agent/report")
    session = _build_session(
        api_key=api_key, ssl_verify=ssl_verify, ca_bundle=ca_bundle
    )
    logger.debug("Sending report: POST %s", url)

    try:
        response = session.post(url, json=report, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Failed to send report: %s", exc)
        return False

    if 200 <= response.status_code < 300:
        logger.debug("Report accepted: HTTP %d", response.status_code)
        return True

    error_msg = _extract_error(response)
    logger.warning(
        "Report rejected: HTTP %d - %s", response.status_code, error_msg
    )
    return False


def get_config(
    server_url: str,
    api_key: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> Dict[str, Any]:
    """Fetch agent configuration from the server.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        Configuration dict from server, or empty dict on failure.
    """
    url = _build_url(server_url, "/api/v1/agent/config")
    session = _build_session(
        api_key=api_key, ssl_verify=ssl_verify, ca_bundle=ca_bundle
    )
    logger.debug("Fetching config: GET %s", url)

    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Failed to fetch config: %s", exc)
        return {}

    if response.status_code != 200:
        logger.warning(
            "Config fetch failed: HTTP %d", response.status_code
        )
        return {}

    try:
        return response.json()
    except ValueError:
        logger.error("Server returned non-JSON config response")
        return {}


def get_commands(
    server_url: str,
    api_key: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> List[Dict[str, Any]]:
    """Fetch pending commands from the server.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        List of command dicts, or empty list on failure.
    """
    url = _build_url(server_url, "/api/v1/agent/commands")
    session = _build_session(
        api_key=api_key, ssl_verify=ssl_verify, ca_bundle=ca_bundle
    )
    logger.debug("Fetching commands: GET %s", url)

    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.debug("Failed to fetch commands: %s", exc)
        return []

    if response.status_code != 200:
        logger.debug("Commands fetch returned HTTP %d", response.status_code)
        return []

    try:
        data = response.json()
    except ValueError:
        return []

    commands = data if isinstance(data, list) else data.get("commands", [])
    if commands:
        logger.info("Received %d pending command(s)", len(commands))
    return commands


def ack_command(
    server_url: str,
    api_key: str,
    cmd_id: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> bool:
    """Acknowledge a command as executed.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        cmd_id: Command ID to acknowledge.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        True if acknowledged successfully, False otherwise.
    """
    url = _build_url(server_url, f"/api/v1/agent/commands/{cmd_id}/ack")
    session = _build_session(
        api_key=api_key, ssl_verify=ssl_verify, ca_bundle=ca_bundle
    )
    logger.debug("Acknowledging command %s: POST %s", cmd_id, url)

    try:
        response = session.post(url, json={"status": "completed"}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("Failed to ack command %s: %s", cmd_id, exc)
        return False

    if 200 <= response.status_code < 300:
        logger.debug("Command %s acknowledged", cmd_id)
        return True

    logger.warning(
        "Command ack failed: HTTP %d for %s", response.status_code, cmd_id
    )
    return False


def upload_logs(
    server_url: str,
    api_key: str,
    log_path: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> bool:
    """Upload agent log file to the server.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        log_path: Path to the log file to upload.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        True if upload succeeded, False otherwise.
    """
    url = _build_url(server_url, "/api/v1/agent/logs/upload")

    if not os.path.isfile(log_path):
        logger.error("Log file not found: %s", log_path)
        return False

    session = _build_session(
        api_key=api_key, ssl_verify=ssl_verify, ca_bundle=ca_bundle
    )
    # Remove Content-Type for multipart upload
    session.headers.pop("Content-Type", None)

    logger.info("Uploading logs: POST %s (file=%s)", url, log_path)

    try:
        with open(log_path, "rb") as fh:
            files = {"file": (os.path.basename(log_path), fh, "text/plain")}
            response = session.post(url, files=files, timeout=60)
    except requests.RequestException as exc:
        logger.error("Failed to upload logs: %s", exc)
        return False
    except OSError as exc:
        logger.error("Failed to read log file %s: %s", log_path, exc)
        return False

    if 200 <= response.status_code < 300:
        logger.info("Logs uploaded successfully")
        return True

    logger.warning("Log upload failed: HTTP %d", response.status_code)
    return False


def _extract_error(response: requests.Response) -> str:
    """Extract error message from an HTTP response.

    Tries to parse JSON error body, falls back to status text.

    Args:
        response: The HTTP response.

    Returns:
        Human-readable error string.
    """
    try:
        data = response.json()
        if isinstance(data, dict):
            return data.get("error", data.get("message", data.get("detail", "")))
        return str(data)
    except (ValueError, AttributeError):
        return response.text[:500] if response.text else f"HTTP {response.status_code}"
