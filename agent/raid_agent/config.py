"""Configuration management for the RAID Monitor Agent.

Handles loading, validating, and saving YAML configuration files.
Supports default values, partial config files, and atomic API key updates.
"""

import logging
import os
import shutil
import tempfile

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/raid-agent/config.yml"

DEFAULT_CONFIG = {
    "server_url": "",
    "api_key": "",
    "storcli_path": "/opt/MegaRAID/storcli/storcli64",
    "collection_interval": 600,
    "ssl_verify": True,
    "ca_bundle": "",
    "debug": False,
    "log_file": "/var/log/raid-agent/agent.log",
    "log_max_size": 10485760,
    "log_backup_count": 5,
}


def load_config(config_path=None):
    """Load configuration from a YAML file, applying defaults for missing keys.

    If the config file does not exist, returns default configuration.

    Args:
        config_path: Path to the YAML config file.
            Defaults to /etc/raid-agent/config.yml.

    Returns:
        dict: Merged configuration with defaults applied for any missing keys.

    Raises:
        yaml.YAMLError: If the config file contains invalid YAML.
        PermissionError: If the config file cannot be read.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    config = dict(DEFAULT_CONFIG)

    if not os.path.isfile(config_path):
        logger.warning(
            "Config file %s not found, using defaults", config_path
        )
        return config

    logger.debug("Loading config from %s", config_path)

    with open(config_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        logger.warning(
            "Config file %s does not contain a mapping, using defaults",
            config_path,
        )
        return config

    # Merge loaded values over defaults
    for key, default_value in DEFAULT_CONFIG.items():
        if key in raw and raw[key] is not None:
            loaded_value = raw[key]
            # Type-check against default to prevent misconfiguration
            if isinstance(default_value, bool):
                config[key] = bool(loaded_value)
            elif isinstance(default_value, int) and not isinstance(default_value, bool):
                try:
                    config[key] = int(loaded_value)
                except (ValueError, TypeError):
                    logger.warning(
                        "Invalid integer value for %s: %r, using default %s",
                        key,
                        loaded_value,
                        default_value,
                    )
            elif isinstance(default_value, str):
                config[key] = str(loaded_value)
            else:
                config[key] = loaded_value

    # Include any extra keys from the file that are not in defaults
    for key in raw:
        if key not in DEFAULT_CONFIG and raw[key] is not None:
            config[key] = raw[key]

    _validate_config(config)
    return config


def _validate_config(config):
    """Validate configuration values and log warnings for issues.

    Args:
        config: Configuration dict to validate in-place.
    """
    # collection_interval must be positive
    if config.get("collection_interval", 0) < 10:
        logger.warning(
            "collection_interval %s is too low, setting to minimum 10 seconds",
            config.get("collection_interval"),
        )
        config["collection_interval"] = 10

    # log_max_size must be positive
    if config.get("log_max_size", 0) < 1024:
        logger.warning(
            "log_max_size %s is too small, setting to 1MB",
            config.get("log_max_size"),
        )
        config["log_max_size"] = 1048576

    # log_backup_count must be non-negative
    if config.get("log_backup_count", 0) < 0:
        config["log_backup_count"] = 0

    # Warn if server_url is empty
    if not config.get("server_url"):
        logger.warning("server_url is not configured")

    # Warn if ca_bundle is set but file does not exist
    ca_bundle = config.get("ca_bundle", "")
    if ca_bundle and not os.path.isfile(ca_bundle):
        logger.warning("ca_bundle path does not exist: %s", ca_bundle)

    # Warn if storcli_path is set but binary does not exist
    storcli_path = config.get("storcli_path", "")
    if storcli_path and not os.path.isfile(storcli_path):
        logger.debug("storcli_path %s does not exist (will auto-detect)", storcli_path)


def save_config(config_path, config):
    """Save the full configuration to a YAML file atomically.

    Writes to a temporary file first, then renames to the target path
    to prevent corruption on crash.

    Args:
        config_path: Path to the YAML config file.
        config: Configuration dict to save.

    Raises:
        OSError: If the file cannot be written.
    """
    config_dir = os.path.dirname(config_path)
    if config_dir:
        os.makedirs(config_dir, mode=0o750, exist_ok=True)

    # Write to temp file in the same directory for atomic rename
    fd, tmp_path = tempfile.mkstemp(
        dir=config_dir, prefix=".config-", suffix=".yml.tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(
                config,
                fh,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        # Preserve permissions of original file if it exists
        if os.path.isfile(config_path):
            stat = os.stat(config_path)
            os.chmod(tmp_path, stat.st_mode)
            try:
                os.chown(tmp_path, stat.st_uid, stat.st_gid)
            except PermissionError:
                pass
        else:
            os.chmod(tmp_path, 0o600)

        shutil.move(tmp_path, config_path)
        logger.debug("Config saved to %s", config_path)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save_api_key(config_path, api_key):
    """Update only the api_key in an existing config file.

    Loads the current config, updates the api_key, and saves back.
    This preserves all other settings and comments structure
    (though YAML comments are lost through round-trip).

    Args:
        config_path: Path to the YAML config file.
        api_key: New API key string.

    Raises:
        OSError: If the file cannot be read or written.
    """
    config = load_config(config_path)
    config["api_key"] = api_key
    save_config(config_path, config)
    logger.info("API key updated in %s", config_path)
