"""
Agent version management service.

Provides endpoints for agents to check for updates and retrieve
the current agent package metadata.
"""
import logging
from typing import Any

from packaging.version import Version, InvalidVersion
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AgentPackage

logger = logging.getLogger(__name__)


def _parse_version(version_str: str) -> Version | None:
    """
    Parse a version string into a packaging.version.Version object.

    Returns None if the version string is invalid.
    """
    try:
        return Version(version_str)
    except InvalidVersion:
        logger.warning("Invalid version string: '%s'", version_str)
        return None


async def get_current_package(db: AsyncSession) -> AgentPackage | None:
    """
    Get the current (latest) agent package marked as the active release.

    Args:
        db: Async database session.

    Returns:
        The current AgentPackage, or None if no package is marked as current.
    """
    result = await db.execute(
        select(AgentPackage).where(
            AgentPackage.is_current == True  # noqa: E712
        )
    )
    package = result.scalar_one_or_none()

    if package is None:
        logger.debug("No current agent package found")

    return package


async def check_update(
    current_version: str,
    db: AsyncSession,
) -> dict[str, Any]:
    """
    Check whether an agent update is available.

    Compares the agent's reported version against the current package
    in the database.

    Args:
        current_version: The version string reported by the agent.
        db: Async database session.

    Returns:
        A dict with:
        - update_available (bool): Whether a newer version exists.
        - current_version (str): The agent's current version.
        - latest_version (str|None): The latest available version.
        - download_url (str|None): URL to download the package.
        - file_hash_sha256 (str|None): SHA256 hash of the package file.
        - file_size (int|None): Package file size in bytes.
        - release_notes (str|None): Release notes for the latest version.
    """
    package = await get_current_package(db)

    if package is None:
        return {
            "update_available": False,
            "current_version": current_version,
            "latest_version": None,
            "message": "No agent package available on server",
        }

    # Compare versions
    agent_ver = _parse_version(current_version)
    latest_ver = _parse_version(package.version)

    update_available = False
    if agent_ver is not None and latest_ver is not None:
        update_available = latest_ver > agent_ver
    elif current_version != package.version:
        # Fallback: simple string comparison if version parsing fails
        update_available = True

    response: dict[str, Any] = {
        "update_available": update_available,
        "current_version": current_version,
        "latest_version": package.version,
        "filename": package.filename,
        "file_hash_sha256": package.file_hash_sha256,
        "file_size": package.file_size,
        "release_notes": package.release_notes,
    }

    if update_available:
        # Build the download URL (agent downloads via API endpoint)
        response["download_url"] = f"/api/v1/agent/package/{package.id}/download"
        response["message"] = f"Update available: v{current_version} -> v{package.version}"
        logger.info(
            "Agent update available: v%s -> v%s",
            current_version,
            package.version,
        )
    else:
        response["download_url"] = None
        response["message"] = "Agent is up to date"

    return response


async def list_packages(
    db: AsyncSession,
    limit: int = 20,
    offset: int = 0,
) -> list[AgentPackage]:
    """
    List all agent packages ordered by upload date (newest first).

    Args:
        db: Async database session.
        limit: Maximum number of packages to return.
        offset: Offset for pagination.

    Returns:
        List of AgentPackage instances.
    """
    result = await db.execute(
        select(AgentPackage)
        .order_by(AgentPackage.uploaded_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())
