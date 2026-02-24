"""storcli64 auto-installer for the RAID Monitor Agent.

Handles locating, downloading, installing, and verifying the storcli64
binary used for RAID controller data collection.
"""

import logging
import os
import shutil
import subprocess
from typing import Optional, Union

import requests
import urllib3

from raid_agent import __version__

logger = logging.getLogger(__name__)

# Standard paths where storcli64 may be installed
STORCLI_SEARCH_PATHS = [
    "/opt/MegaRAID/storcli/storcli64",
    "/opt/MegaRAID/storcli64/storcli64",
    "/usr/local/bin/storcli64",
    "/usr/bin/storcli64",
    "/usr/sbin/storcli64",
]

# Temporary download location
STORCLI_RPM_TMP = "/tmp/storcli64.rpm"

# storcli64 verification timeout
VERIFY_TIMEOUT = 15


def find_storcli(config_path: str = "") -> Optional[str]:
    """Search for the storcli64 binary on the system.

    Search order:
        1. Configured path (from config file)
        2. Standard installation paths
        3. System PATH (via `which`)

    Args:
        config_path: Path from configuration, checked first if non-empty.

    Returns:
        Absolute path to storcli64 binary, or None if not found.
    """
    # Check configured path first
    if config_path and os.path.isfile(config_path) and os.access(config_path, os.X_OK):
        logger.debug("storcli64 found at configured path: %s", config_path)
        return config_path

    # Check standard paths
    for path in STORCLI_SEARCH_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            logger.debug("storcli64 found at standard path: %s", path)
            return path

    # Check system PATH
    which_path = shutil.which("storcli64")
    if which_path:
        logger.debug("storcli64 found in PATH: %s", which_path)
        return which_path

    # Also check for perccli64 (Dell equivalent) as fallback
    dell_paths = [
        "/opt/MegaRAID/perccli/perccli64",
        "/opt/dell/perccli/perccli64",
    ]
    for path in dell_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            logger.debug("perccli64 (Dell equivalent) found: %s", path)
            return path

    which_perccli = shutil.which("perccli64")
    if which_perccli:
        logger.debug("perccli64 found in PATH: %s", which_perccli)
        return which_perccli

    logger.warning("storcli64 not found on system")
    return None


def install_storcli(
    server_url: str,
    api_key: str,
    ssl_verify: Union[bool, str] = True,
    ca_bundle: str = "",
) -> str:
    """Download and install storcli64 from the central server.

    Downloads the storcli64 RPM package from the server, saves it
    to a temporary location, and installs it via rpm.

    Args:
        server_url: Base server URL.
        api_key: Authentication API key.
        ssl_verify: Whether to verify SSL certificates.
        ca_bundle: Path to custom CA bundle.

    Returns:
        Path to installed storcli64 binary.

    Raises:
        RuntimeError: If download or installation fails.
    """
    download_url = f"{server_url.rstrip('/')}/api/v1/agent/storcli/download"

    logger.info("Downloading storcli64 RPM from %s", download_url)

    # Prepare SSL verification
    verify = ca_bundle if (ca_bundle and os.path.isfile(ca_bundle)) else ssl_verify
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Download RPM
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
        raise RuntimeError(f"Failed to download storcli64 RPM: {exc}") from exc

    if response.status_code != 200:
        raise RuntimeError(
            f"storcli64 download failed: HTTP {response.status_code}"
        )

    # Verify content type suggests an RPM package
    content_type = response.headers.get("Content-Type", "")
    content_length = response.headers.get("Content-Length", "0")

    if int(content_length or 0) < 1024:
        raise RuntimeError(
            f"Downloaded file too small ({content_length} bytes), likely not a valid RPM"
        )

    # Save to temp file
    try:
        with open(STORCLI_RPM_TMP, "wb") as fh:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    fh.write(chunk)
    except OSError as exc:
        raise RuntimeError(f"Failed to save RPM to {STORCLI_RPM_TMP}: {exc}") from exc

    file_size = os.path.getsize(STORCLI_RPM_TMP)
    logger.info("Downloaded storcli64 RPM: %d bytes -> %s", file_size, STORCLI_RPM_TMP)

    # Verify the file is actually an RPM
    try:
        verify_result = subprocess.run(
            ["rpm", "-qip", STORCLI_RPM_TMP],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if verify_result.returncode != 0:
            logger.warning(
                "RPM verification output: %s",
                verify_result.stderr.strip()[:200],
            )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("Could not verify RPM package: %s", exc)

    # Install RPM
    logger.info("Installing storcli64 RPM: rpm -ivh %s", STORCLI_RPM_TMP)
    try:
        install_result = subprocess.run(
            ["rpm", "-ivh", STORCLI_RPM_TMP],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"RPM install command failed: {exc}") from exc

    if install_result.returncode != 0:
        stderr = install_result.stderr.strip()
        stdout = install_result.stdout.strip()
        # Check if it is already installed (rpm returns non-zero for this)
        if "already installed" in stderr or "already installed" in stdout:
            logger.info("storcli64 RPM is already installed")
        else:
            raise RuntimeError(
                f"RPM install failed (exit {install_result.returncode}): "
                f"{stderr or stdout}"
            )

    logger.info("RPM install output: %s", install_result.stdout.strip()[:200])

    # Clean up temp file
    try:
        os.unlink(STORCLI_RPM_TMP)
    except OSError:
        pass

    # Find the installed binary
    installed_path = find_storcli()
    if installed_path is None:
        raise RuntimeError(
            "storcli64 RPM installed but binary not found in standard paths"
        )

    logger.info("storcli64 installed successfully at %s", installed_path)
    return installed_path


def verify_storcli(path: str) -> bool:
    """Verify that the storcli64 binary at the given path can execute.

    Runs `storcli64 show` and checks for a zero exit code.

    Args:
        path: Full path to the storcli64 binary.

    Returns:
        True if storcli64 executed successfully, False otherwise.
    """
    if not os.path.isfile(path):
        logger.error("storcli64 binary does not exist: %s", path)
        return False

    if not os.access(path, os.X_OK):
        logger.error("storcli64 binary is not executable: %s", path)
        return False

    logger.debug("Verifying storcli64: %s show", path)

    try:
        result = subprocess.run(
            [path, "show"],
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("storcli64 verification timed out after %ds", VERIFY_TIMEOUT)
        return False
    except FileNotFoundError:
        logger.error("storcli64 binary not found: %s", path)
        return False
    except OSError as exc:
        logger.error("storcli64 verification failed: %s", exc)
        return False

    if result.returncode == 0:
        logger.debug("storcli64 verification passed")
        return True

    # storcli64 may return non-zero if no controller is present,
    # but still be a valid binary. Check if output looks like storcli.
    output = result.stdout + result.stderr
    if "StorCli" in output or "storcli" in output.lower() or "MegaRAID" in output:
        logger.debug(
            "storcli64 returned exit code %d but output looks valid",
            result.returncode,
        )
        return True

    logger.error(
        "storcli64 verification failed: exit code %d, output: %s",
        result.returncode,
        output[:200],
    )
    return False
