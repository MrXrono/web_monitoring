"""Self-update mechanism for the RAID Monitor Agent.

Handles checking for available updates from the central server,
downloading new RPM packages, verifying integrity via SHA256,
and applying updates through rpm.
"""

import hashlib
import logging
import os
import subprocess
from typing import Any, Dict, Optional, Union

import requests
import urllib3

from raid_agent import __version__

# Suppress SSL warnings — agent must work with self-signed certificates
# (consistent with reporter.py behavior)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Temporary download location for update RPM
UPDATE_RPM_TMP = "/tmp/raid-agent-new.rpm"

# Chunk size for hashing and downloading
CHUNK_SIZE = 8192


def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple.

    Supports standard semver-like versions: major.minor.patch

    Args:
        version_str: Version string (e.g., "1.2.3").

    Returns:
        Tuple of integers for comparison, or (0,) on parse failure.
    """
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0,)


def check_update(
    server_url: str,
    api_key: str,
    current_version: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> Optional[Dict[str, Any]]:
    """Check if an agent update is available on the server.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        current_version: Currently running agent version string.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        Dict with update info (version, sha256, size, changelog) if an
        update is available, or None if current version is up to date.

    Raises:
        requests.RequestException: On network errors.
    """
    url = f"{server_url.rstrip('/')}/api/v1/agent/update/check"

    # Always trust self-signed certificates (same as reporter.py)
    # Use ca_bundle only if explicitly configured and file exists
    verify = ca_bundle if (ca_bundle and os.path.isfile(ca_bundle)) else False

    logger.debug("Checking for updates: GET %s (current=%s)", url, current_version)

    try:
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": f"raid-agent/{__version__}",
            },
            params={"current_version": current_version},
            verify=verify,
            timeout=30,
        )
    except requests.RequestException as exc:
        logger.warning("Update check request failed: %s", exc)
        raise

    if response.status_code == 204:
        # No content = no update available
        logger.debug("No update available (HTTP 204)")
        return None

    if response.status_code != 200:
        logger.debug("Update check returned HTTP %d", response.status_code)
        return None

    try:
        data = response.json()
    except ValueError:
        logger.warning("Update check returned non-JSON response")
        return None

    new_version = data.get("version", "")
    if not new_version:
        logger.debug("Update response missing version field")
        return None

    # Compare versions
    current_tuple = _parse_version(current_version)
    new_tuple = _parse_version(new_version)

    if new_tuple <= current_tuple:
        logger.debug(
            "Server version %s is not newer than current %s",
            new_version,
            current_version,
        )
        return None

    logger.info(
        "Update available: %s -> %s (sha256=%s)",
        current_version,
        new_version,
        data.get("sha256", "n/a")[:16],
    )

    return {
        "version": new_version,
        "sha256": data.get("sha256", ""),
        "size": data.get("size", 0),
        "changelog": data.get("changelog", ""),
        "url": data.get("download_url", ""),
    }


def do_update(
    server_url: str,
    api_key: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> bool:
    """Download and apply an agent self-update.

    Steps:
        1. Download new RPM from server
        2. Verify SHA256 checksum
        3. Install via `rpm -Uvh`
        4. The RPM postinstall script handles service restart

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        True if update was applied successfully, False otherwise.
    """
    # Always trust self-signed certificates (same as reporter.py)
    verify = ca_bundle if (ca_bundle and os.path.isfile(ca_bundle)) else False

    # First, get update metadata (including expected sha256)
    try:
        update_info = check_update(
            server_url=server_url,
            api_key=api_key,
            current_version=__version__,
            ssl_verify=ssl_verify,
            ca_bundle=ca_bundle,
        )
    except Exception:
        logger.exception("Failed to check for update info before download")
        return False

    if update_info is None:
        logger.info("No update available")
        return False

    expected_sha256 = update_info.get("sha256", "")
    new_version = update_info.get("version", "unknown")

    # Download new RPM
    download_url = update_info.get("url", "")
    if not download_url:
        download_url = f"{server_url.rstrip('/')}/api/v1/agent/update/download"

    logger.info("Downloading agent update v%s from %s", new_version, download_url)

    try:
        response = requests.get(
            download_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": f"raid-agent/{__version__}",
            },
            verify=verify,
            timeout=120,
            stream=True,
        )
    except requests.RequestException as exc:
        logger.error("Update download failed: %s", exc)
        return False

    if response.status_code != 200:
        logger.error("Update download returned HTTP %d", response.status_code)
        return False

    # Save to temp file and compute SHA256
    sha256_hash = hashlib.sha256()
    try:
        with open(UPDATE_RPM_TMP, "wb") as fh:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    fh.write(chunk)
                    sha256_hash.update(chunk)
    except OSError as exc:
        logger.error("Failed to save update RPM: %s", exc)
        return False

    computed_sha256 = sha256_hash.hexdigest()
    file_size = os.path.getsize(UPDATE_RPM_TMP)
    logger.info(
        "Downloaded update RPM: %d bytes, SHA256=%s", file_size, computed_sha256[:16]
    )

    # Verify SHA256 checksum
    if expected_sha256:
        if computed_sha256.lower() != expected_sha256.lower():
            logger.error(
                "SHA256 mismatch! Expected=%s, Got=%s",
                expected_sha256,
                computed_sha256,
            )
            _cleanup_tmp()
            return False
        logger.info("SHA256 checksum verified successfully")
    else:
        logger.warning("No expected SHA256 provided by server, skipping verification")

    # Verify the downloaded file is a valid RPM
    try:
        verify_result = subprocess.run(
            ["rpm", "-qip", UPDATE_RPM_TMP],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if verify_result.returncode != 0:
            logger.error(
                "Downloaded file is not a valid RPM: %s",
                verify_result.stderr.strip()[:200],
            )
            _cleanup_tmp()
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Could not verify RPM package: %s", exc)

    # Apply update
    logger.info("Applying update: rpm -Uvh %s", UPDATE_RPM_TMP)
    try:
        install_result = subprocess.run(
            ["rpm", "-Uvh", UPDATE_RPM_TMP],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("RPM upgrade timed out")
        _cleanup_tmp()
        return False
    except FileNotFoundError:
        logger.error("rpm command not found")
        _cleanup_tmp()
        return False

    if install_result.returncode != 0:
        stderr = install_result.stderr.strip()
        stdout = install_result.stdout.strip()
        logger.error(
            "RPM upgrade failed (exit %d): %s",
            install_result.returncode,
            stderr or stdout,
        )
        _cleanup_tmp()
        return False

    logger.info("RPM upgrade output: %s", install_result.stdout.strip()[:200])

    # Clean up temp file
    _cleanup_tmp()

    # Restart the service - the RPM postinstall script should handle this,
    # but we trigger it explicitly as a safety measure
    logger.info("Requesting service restart via systemctl...")
    try:
        subprocess.run(
            ["systemctl", "restart", "raid-agent"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning(
            "Could not restart service (RPM postinstall should handle this): %s", exc
        )

    return True


def _cleanup_tmp():
    """Remove the temporary update RPM file."""
    try:
        if os.path.isfile(UPDATE_RPM_TMP):
            os.unlink(UPDATE_RPM_TMP)
            logger.debug("Cleaned up %s", UPDATE_RPM_TMP)
    except OSError as exc:
        logger.warning("Failed to clean up %s: %s", UPDATE_RPM_TMP, exc)
