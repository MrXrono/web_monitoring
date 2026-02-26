#!/usr/bin/env python3
"""RAID Monitor Agent - Entry point (systemd service daemon).

This module provides the main entry point for the RAID monitoring agent.
It handles CLI argument parsing, daemon lifecycle, signal handling,
periodic data collection, and communication with the central server.
"""

import argparse
import logging
import logging.handlers
import os
import signal
import sys
import time
import threading
from pathlib import Path

from raid_agent import __version__
from raid_agent.config import load_config, save_api_key, DEFAULT_CONFIG_PATH
from raid_agent.collector import collect_all, get_storcli_version
from raid_agent.system_info import get_system_info
from raid_agent.reporter import (
    register,
    send_report,
    get_commands,
    ack_command,
)
from raid_agent.installer import (
    find_storcli, install_storcli, verify_storcli,
    find_smartctl, install_smartctl, verify_smartctl,
)
from raid_agent.updater import check_update, do_update
from raid_agent.smartctl_collector import collect_software_raid, get_smartctl_version

logger = logging.getLogger("raid_agent")

# Global shutdown event for graceful termination
_shutdown_event = threading.Event()


def parse_args(argv=None):
    """Parse command-line arguments.

    Args:
        argv: Argument list. Defaults to sys.argv[1:].

    Returns:
        argparse.Namespace with parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="raid-agent",
        description="RAID Monitor Agent - collects RAID controller data and reports to server",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to config file (default: %(default)s)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single collection cycle and exit",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Register this agent with the server and save API key",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"raid-agent {__version__}",
    )
    return parser.parse_args(argv)


def setup_logging(config):
    """Configure logging with file rotation and optional console output.

    Args:
        config: Agent configuration dict.
    """
    log_level = logging.DEBUG if config.get("debug", False) else logging.INFO
    log_file = config.get("log_file", "/var/log/raid-agent/agent.log")
    log_max_size = config.get("log_max_size", 10485760)
    log_backup_count = config.get("log_backup_count", 5)

    root_logger = logging.getLogger("raid_agent")
    root_logger.setLevel(log_level)

    # Clear any existing handlers
    root_logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler with rotation
    log_dir = os.path.dirname(log_file)
    if log_dir:
        try:
            os.makedirs(log_dir, mode=0o750, exist_ok=True)
        except OSError as exc:
            root_logger.warning("Cannot create log directory %s: %s", log_dir, exc)
            return

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=log_max_size,
            backupCount=log_backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError as exc:
        root_logger.warning("Cannot open log file %s: %s", log_file, exc)


def _signal_handler(signum, _frame):
    """Handle SIGTERM and SIGINT for graceful shutdown."""
    sig_name = signal.Signals(signum).name
    logger.info("Received %s, initiating graceful shutdown...", sig_name)
    _shutdown_event.set()


def ensure_storcli(config):
    """Ensure storcli64 binary is available.

    Searches for the binary, attempts auto-install from server if missing,
    and verifies it can execute.

    Args:
        config: Agent configuration dict.

    Returns:
        Path to storcli64 binary, or None if unavailable.
    """
    storcli_path = find_storcli(config.get("storcli_path", ""))

    if storcli_path is None:
        logger.warning("storcli64 not found on system, attempting auto-install...")
        server_url = config.get("server_url", "")
        api_key = config.get("api_key", "")
        if server_url and api_key:
            try:
                storcli_path = install_storcli(
                    server_url, api_key,
                    ssl_verify=config.get("ssl_verify", True),
                    ca_bundle=config.get("ca_bundle", ""),
                )
                logger.info("storcli64 installed at %s", storcli_path)
            except Exception:
                logger.exception("Failed to auto-install storcli64")
                return None
        else:
            logger.error(
                "Cannot auto-install storcli64: server_url or api_key not configured"
            )
            return None

    if not verify_storcli(storcli_path):
        logger.error("storcli64 at %s failed verification", storcli_path)
        return None

    return storcli_path


def ensure_smartctl(config):
    """Ensure smartctl binary is available.

    Searches for the binary and attempts auto-install via package manager
    if missing, then verifies it can execute.

    Args:
        config: Agent configuration dict.

    Returns:
        Path to smartctl binary, or None if unavailable.
    """
    smartctl_path = find_smartctl(config.get("smartctl_path", ""))

    if smartctl_path is None:
        logger.warning("smartctl not found on system, attempting auto-install...")
        try:
            smartctl_path = install_smartctl()
            logger.info("smartctl installed at %s", smartctl_path)
        except Exception:
            logger.exception("Failed to auto-install smartctl (smartmontools)")
            return None

    if not verify_smartctl(smartctl_path):
        logger.error("smartctl at %s failed verification", smartctl_path)
        return None

    return smartctl_path


def do_register(config, config_path):
    """Register this agent with the central server.

    Collects system info, sends registration request, and saves
    the returned API key to the config file.

    Args:
        config: Agent configuration dict.
        config_path: Path to the config file for saving the API key.

    Returns:
        True on success, False on failure.
    """
    server_url = config.get("server_url", "")
    if not server_url:
        logger.error("server_url is not configured. Cannot register.")
        return False

    logger.info("Gathering system information for registration...")
    sys_info = get_system_info()

    logger.info(
        "Registering with server %s as %s (%s)...",
        server_url,
        sys_info.get("hostname", "unknown"),
        sys_info.get("ip_address", "unknown"),
    )

    try:
        api_key = register(
            server_url=server_url,
            hostname=sys_info.get("hostname", "unknown"),
            ip=sys_info.get("ip_address", ""),
            os_info={
                "os_name": sys_info.get("os_name", ""),
                "os_version": sys_info.get("os_version", ""),
                "kernel": sys_info.get("kernel", ""),
                "fqdn": sys_info.get("fqdn", ""),
            },
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )
    except Exception:
        logger.exception("Registration failed")
        return False

    if not api_key:
        logger.error("Registration returned empty API key")
        return False

    save_api_key(config_path, api_key)
    logger.info("Registration successful. API key saved to %s", config_path)
    return True


def run_collection_cycle(config, storcli_path, smartctl_path=""):
    """Execute a single data collection and reporting cycle.

    Args:
        config: Agent configuration dict.
        storcli_path: Path to storcli64 binary.
        smartctl_path: Path to smartctl binary (optional).

    Returns:
        True if report was sent successfully, False otherwise.
    """
    server_url = config.get("server_url", "")
    api_key = config.get("api_key", "")

    if not server_url or not api_key:
        logger.error("server_url or api_key not configured. Skipping cycle.")
        return False

    # Collect RAID data
    logger.info("Starting data collection cycle...")
    try:
        report = collect_all(storcli_path)
    except Exception:
        logger.exception("Data collection failed")
        return False

    # Enrich with system info
    try:
        sys_info = get_system_info()
    except Exception:
        logger.exception("Failed to collect system info")
        sys_info = {}

    # Add required top-level fields for server schema
    report["hostname"] = sys_info.get("hostname", "unknown")
    report["ip_address"] = sys_info.get("ip_address", "")
    report["fqdn"] = sys_info.get("fqdn", "")
    report["os"] = {
        "name": sys_info.get("os_name", ""),
        "version": sys_info.get("os_version", ""),
        "kernel": sys_info.get("kernel", ""),
    }
    report["agent_version"] = __version__
    report["storcli_version"] = get_storcli_version(storcli_path)
    report["smartctl_version"] = get_smartctl_version(smartctl_path) if smartctl_path else ""

    # Collect software RAID + SMART data
    try:
        sw_data = collect_software_raid(smartctl_path)
        report["software_raid"] = sw_data.get("software_raid_arrays", [])
        report["smart_drives"] = sw_data.get("smart_drives", [])
        logger.info(
            "Software RAID: %d arrays, SMART: %d drives",
            len(report["software_raid"]),
            len(report["smart_drives"]),
        )
    except Exception:
        logger.warning("Software RAID / SMART collection failed", exc_info=True)
        report["software_raid"] = []
        report["smart_drives"] = []

    report["cpu_model"] = sys_info.get("cpu_model", "")
    report["cpu_cores"] = sys_info.get("cpu_cores", 0)
    report["ram_total_gb"] = sys_info.get("ram_total_gb", 0.0)
    report["uptime_seconds"] = int(sys_info.get("uptime_seconds", 0))
    report["last_os_update"] = sys_info.get("last_os_update")
    report["collection_timestamp"] = time.time()

    # Send report
    logger.info("Sending report to %s...", server_url)
    try:
        success = send_report(
            server_url=server_url,
            api_key=api_key,
            report=report,
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )
    except Exception:
        logger.exception("Failed to send report")
        return False

    if success:
        logger.info("Report sent successfully")
    else:
        logger.warning("Server rejected the report")

    return success


def process_commands(config):
    """Check for and execute pending commands from the server.

    Args:
        config: Agent configuration dict.
    """
    server_url = config.get("server_url", "")
    api_key = config.get("api_key", "")

    if not server_url or not api_key:
        return

    try:
        commands = get_commands(
            server_url=server_url,
            api_key=api_key,
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )
    except Exception:
        logger.warning("Failed to fetch commands from server", exc_info=True)
        return

    if not commands:
        return

    for cmd in commands:
        cmd_id = cmd.get("id", "")
        cmd_type = cmd.get("type", "")
        logger.info("Processing command %s: %s", cmd_id, cmd_type)

        try:
            _execute_command(cmd, config)
            if cmd_id:
                ack_command(
                    server_url=server_url,
                    api_key=api_key,
                    cmd_id=cmd_id,
                    ssl_verify=config.get("ssl_verify", True),
                    ca_bundle=config.get("ca_bundle", ""),
                )
                logger.info("Command %s acknowledged", cmd_id)
        except Exception:
            logger.exception("Failed to execute command %s", cmd_id)


def _execute_command(cmd, config):
    """Execute a single server command.

    Supported command types:
    - collect_now: Trigger immediate collection cycle
    - update_config: Update agent configuration values
    - upload_logs: Upload agent log file to server
    - restart: Request agent restart via systemd

    Args:
        cmd: Command dict from server.
        config: Agent configuration dict.
    """
    cmd_type = cmd.get("type", "")

    if cmd_type == "collect_now":
        logger.info("Server requested immediate collection")
        storcli_path = ensure_storcli(config)
        smartctl_path = ensure_smartctl(config) or ""
        if storcli_path:
            run_collection_cycle(config, storcli_path, smartctl_path)
        else:
            logger.error("Cannot collect: storcli64 not found")

    elif cmd_type == "update_config":
        params = cmd.get("params", {})
        logger.info("Server requested config update: %s", list(params.keys()))
        # Only allow safe config keys to be updated remotely
        safe_keys = {"collection_interval", "debug", "ssl_verify"}
        for key, value in params.items():
            if key in safe_keys:
                config[key] = value
                logger.info("Config updated: %s = %s", key, value)
                # Apply debug mode change immediately
                if key == "debug":
                    new_level = logging.DEBUG if value else logging.INFO
                    logging.getLogger("raid_agent").setLevel(new_level)
                    logger.info("Log level changed to %s", logging.getLevelName(new_level))
            else:
                logger.warning("Refusing to update unsafe config key: %s", key)

    elif cmd_type == "upload_logs":
        from raid_agent.reporter import upload_logs

        log_file = config.get("log_file", "/var/log/raid-agent/agent.log")
        logger.info("Server requested log upload: %s", log_file)
        upload_logs(
            server_url=config.get("server_url", ""),
            api_key=config.get("api_key", ""),
            log_path=log_file,
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )

    elif cmd_type == "restart":
        logger.info("Server requested agent restart")
        _shutdown_event.set()

    else:
        logger.warning("Unknown command type: %s", cmd_type)


def check_for_updates(config):
    """Check for and apply agent self-updates.

    Args:
        config: Agent configuration dict.
    """
    server_url = config.get("server_url", "")
    api_key = config.get("api_key", "")

    if not server_url or not api_key:
        return

    try:
        update_info = check_update(
            server_url=server_url,
            api_key=api_key,
            current_version=__version__,
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )
    except Exception:
        logger.warning("Update check failed", exc_info=True)
        return

    if update_info is None:
        logger.debug("No updates available")
        return

    new_version = update_info.get("version", "unknown")
    logger.info("Update available: %s -> %s", __version__, new_version)

    try:
        success = do_update(
            server_url=server_url,
            api_key=api_key,
            ssl_verify=config.get("ssl_verify", True),
            ca_bundle=config.get("ca_bundle", ""),
        )
        if success:
            logger.info(
                "Update to %s applied. Service will restart via RPM postinstall.",
                new_version,
            )
        else:
            logger.warning("Update to %s failed", new_version)
    except Exception:
        logger.exception("Self-update failed")


def _command_poll_loop(config):
    """Background thread: poll server for commands every 30 seconds.

    This ensures commands (debug toggle, log upload requests) are
    picked up quickly without waiting for the full collection interval.
    """
    poll_interval = 30
    logger.info("Command poll thread started (interval=%ds)", poll_interval)

    while not _shutdown_event.is_set():
        if _shutdown_event.wait(timeout=poll_interval):
            break
        try:
            process_commands(config)
        except Exception:
            logger.warning("Command poll error", exc_info=True)

    logger.info("Command poll thread exited")


def daemon_loop(config, storcli_path):
    """Main daemon loop: collect, report, check updates.

    Commands are processed in a separate thread every 30s for fast response.
    Runs until _shutdown_event is set (by signal handler or server command).

    Args:
        config: Agent configuration dict.
        storcli_path: Path to storcli64 binary.
    """
    interval = config.get("collection_interval", 600)
    logger.info(
        "Starting daemon loop (interval=%ds, storcli=%s)", interval, storcli_path
    )

    # Periodic storcli re-check: every hour (3600s)
    STORCLI_RECHECK_INTERVAL = 3600
    last_storcli_check = time.monotonic()

    # Periodic smartctl re-check: every hour (3600s)
    SMARTCTL_RECHECK_INTERVAL = 3600
    last_smartctl_check = time.monotonic()
    smartctl_path = ensure_smartctl(config) or ""

    # Start background command polling thread
    cmd_thread = threading.Thread(
        target=_command_poll_loop, args=(config,), daemon=True, name="cmd-poll"
    )
    cmd_thread.start()

    while not _shutdown_event.is_set():
        cycle_start = time.monotonic()

        # Periodic storcli availability check (every hour)
        if cycle_start - last_storcli_check >= STORCLI_RECHECK_INTERVAL or not storcli_path:
            last_storcli_check = cycle_start
            new_path = ensure_storcli(config)
            if new_path and new_path != storcli_path:
                logger.info("storcli64 path updated: %s -> %s", storcli_path or "(none)", new_path)
                storcli_path = new_path
            elif not new_path and storcli_path:
                logger.warning("storcli64 disappeared from %s, RAID collection disabled", storcli_path)
                storcli_path = ""
            elif not new_path and not storcli_path:
                logger.debug("storcli64 still not available, will retry in %ds", STORCLI_RECHECK_INTERVAL)

        # Periodic smartctl availability check (every hour)
        if cycle_start - last_smartctl_check >= SMARTCTL_RECHECK_INTERVAL or not smartctl_path:
            last_smartctl_check = cycle_start
            new_smartctl = ensure_smartctl(config)
            if new_smartctl and new_smartctl != smartctl_path:
                logger.info("smartctl path updated: %s -> %s", smartctl_path or "(none)", new_smartctl)
                smartctl_path = new_smartctl
            elif not new_smartctl and smartctl_path:
                logger.warning("smartctl disappeared from %s, SMART collection disabled", smartctl_path)
                smartctl_path = ""
            elif not new_smartctl and not smartctl_path:
                logger.debug("smartctl still not available, will retry in %ds", SMARTCTL_RECHECK_INTERVAL)

        # Run collection and reporting
        try:
            run_collection_cycle(config, storcli_path, smartctl_path)
        except Exception:
            logger.exception("Unhandled error in collection cycle")

        # Check for self-updates
        try:
            check_for_updates(config)
        except Exception:
            logger.exception("Unhandled error checking for updates")

        # Sleep for the remaining interval
        elapsed = time.monotonic() - cycle_start
        remaining = max(0, interval - elapsed)
        logger.debug("Cycle took %.1fs, sleeping %.1fs", elapsed, remaining)

        # Wait with early exit on shutdown signal
        if _shutdown_event.wait(timeout=remaining):
            break

    logger.info("Daemon loop exited")
    cmd_thread.join(timeout=5)


def main(argv=None):
    """Main entry point for the RAID monitoring agent.

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Returns:
        Exit code (0 for success, 1 for error).
    """
    args = parse_args(argv)

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"ERROR: Failed to load config from {args.config}: {exc}", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(config)
    logger.info("RAID Monitor Agent v%s starting", __version__)
    logger.debug("Config loaded from %s", args.config)

    # Install signal handlers
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Handle --register mode
    if args.register:
        success = do_register(config, args.config)
        return 0 if success else 1

    # Validate required config
    if not config.get("server_url"):
        logger.error("server_url is not configured. Run with --register first.")
        return 1

    if not config.get("api_key"):
        logger.error("api_key is not configured. Run with --register first.")
        return 1

    # Ensure storcli64 is available
    storcli_path = ensure_storcli(config)
    if storcli_path is None:
        logger.warning("storcli64 is not available. Agent will run but RAID data collection is disabled.")
        storcli_path = ""

    # Ensure smartctl is available
    smartctl_path = ensure_smartctl(config)
    if smartctl_path is None:
        logger.warning("smartctl is not available. Agent will run but SMART data collection is disabled.")
    else:
        logger.info("smartctl available at %s", smartctl_path)

    # Handle --once mode
    if args.once:
        logger.info("Running single collection cycle (--once)")
        success = run_collection_cycle(config, storcli_path)
        return 0 if success else 1

    # Run as daemon
    logger.info("Entering daemon mode")
    daemon_loop(config, storcli_path)
    logger.info("RAID Monitor Agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
