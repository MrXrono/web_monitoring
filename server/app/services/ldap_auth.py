"""
LDAP authentication service.

Authenticates users against an Active Directory / LDAP server using
settings stored in the database. Supports bind authentication and
group-based admin role assignment.
"""
import asyncio
import logging
from typing import Any

import ldap3
from ldap3 import Server as LdapServer, Connection, ALL, SUBTREE
from ldap3.core.exceptions import (
    LDAPException,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPInvalidCredentialsResult,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models import Setting
from app.services.encryption import decrypt_value

logger = logging.getLogger(__name__)

# LDAP settings keys in the database
LDAP_SETTINGS_KEYS = {
    "ldap_enabled": "ldap_enabled",
    "ldap_server_url": "ldap_server_url",
    "ldap_bind_dn": "ldap_bind_dn",
    "ldap_bind_password": "ldap_bind_password",
    "ldap_search_base": "ldap_search_base",
    "ldap_user_filter": "ldap_user_filter",
    "ldap_admin_group": "ldap_admin_group",
    "ldap_use_ssl": "ldap_use_ssl",
    "ldap_start_tls": "ldap_start_tls",
    "ldap_display_name_attr": "ldap_display_name_attr",
    "ldap_email_attr": "ldap_email_attr",
}

DEFAULT_USER_FILTER = "(sAMAccountName={username})"
DEFAULT_DISPLAY_NAME_ATTR = "displayName"
DEFAULT_EMAIL_ATTR = "mail"


async def _get_ldap_settings(db: AsyncSession | None = None) -> dict[str, str]:
    """
    Load LDAP configuration from the settings table.

    Returns a dict with decrypted values where applicable.
    """
    close_session = False
    if db is None:
        db = async_session()
        close_session = True

    try:
        result = await db.execute(
            select(Setting).where(Setting.category == "ldap")
        )
        settings_rows = result.scalars().all()

        cfg: dict[str, str] = {}
        for row in settings_rows:
            value = row.value
            if row.is_encrypted and value:
                try:
                    value = decrypt_value(value)
                except Exception:
                    logger.error("Failed to decrypt LDAP setting '%s'", row.key)
                    value = ""
            cfg[row.key] = value or ""

        return cfg
    finally:
        if close_session:
            await db.close()


def _build_ldap_connection(
    server_url: str,
    use_ssl: bool = False,
    start_tls: bool = False,
) -> tuple[LdapServer, dict]:
    """
    Build an ldap3 Server object and connection kwargs.

    Args:
        server_url: LDAP server URL (ldap://host:port or ldaps://host:port).
        use_ssl: Whether to use SSL.
        start_tls: Whether to use STARTTLS.

    Returns:
        Tuple of (LdapServer, connection_kwargs).
    """
    if server_url.startswith("ldaps://"):
        use_ssl = True

    server = LdapServer(
        server_url,
        use_ssl=use_ssl,
        get_info=ALL,
        connect_timeout=10,
    )

    conn_kwargs: dict[str, Any] = {
        "server": server,
        "auto_bind": False,
        "receive_timeout": 15,
    }

    return server, conn_kwargs


def _sync_authenticate(
    server_url: str,
    bind_dn: str,
    bind_password: str,
    search_base: str,
    user_filter: str,
    username: str,
    password: str,
    admin_group: str = "",
    use_ssl: bool = False,
    start_tls: bool = False,
    display_name_attr: str = DEFAULT_DISPLAY_NAME_ATTR,
    email_attr: str = DEFAULT_EMAIL_ATTR,
) -> dict | None:
    """
    Synchronous LDAP authentication (runs in thread executor).

    1. Bind with service account to search for the user.
    2. Attempt bind with user's own credentials.
    3. Check group membership if admin_group is configured.

    Returns user info dict on success, None on failure.
    """
    _, conn_kwargs = _build_ldap_connection(server_url, use_ssl, start_tls)

    # Step 1: Service account bind + user search
    try:
        service_conn = Connection(
            **conn_kwargs,
            user=bind_dn,
            password=bind_password,
        )
        if not service_conn.bind():
            logger.error(
                "LDAP service account bind failed: %s",
                service_conn.result.get("description", "unknown"),
            )
            return None

        if start_tls and not use_ssl:
            service_conn.start_tls()

    except LDAPSocketOpenError as exc:
        logger.error("Cannot connect to LDAP server %s: %s", server_url, exc)
        return None
    except LDAPException as exc:
        logger.error("LDAP service bind error: %s", exc)
        return None

    try:
        # Build the search filter
        search_filter = user_filter.replace("{username}", username)

        service_conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                display_name_attr,
                email_attr,
                "memberOf",
                "sAMAccountName",
                "userPrincipalName",
                "distinguishedName",
            ],
        )

        if not service_conn.entries:
            logger.info("LDAP user '%s' not found", username)
            return None

        user_entry = service_conn.entries[0]
        user_dn = str(user_entry.entry_dn)

    except LDAPException as exc:
        logger.error("LDAP search error: %s", exc)
        return None
    finally:
        try:
            service_conn.unbind()
        except Exception:
            pass

    # Step 2: Bind with user credentials
    try:
        user_conn = Connection(
            **conn_kwargs,
            user=user_dn,
            password=password,
        )
        if not user_conn.bind():
            logger.info(
                "LDAP authentication failed for user '%s': invalid credentials",
                username,
            )
            return None

        if start_tls and not use_ssl:
            user_conn.start_tls()

    except (LDAPBindError, LDAPInvalidCredentialsResult):
        logger.info("LDAP authentication failed for user '%s': invalid credentials", username)
        return None
    except LDAPSocketOpenError as exc:
        logger.error("Cannot connect to LDAP server for user bind: %s", exc)
        return None
    except LDAPException as exc:
        logger.error("LDAP user bind error: %s", exc)
        return None
    finally:
        try:
            user_conn.unbind()
        except Exception:
            pass

    # Step 3: Extract user attributes
    display_name = ""
    email = ""
    try:
        if hasattr(user_entry, display_name_attr):
            display_name = str(getattr(user_entry, display_name_attr, ""))
        if hasattr(user_entry, email_attr):
            email = str(getattr(user_entry, email_attr, ""))
    except Exception:
        pass

    # Step 4: Check admin group membership
    is_admin = False
    if admin_group:
        try:
            member_of = user_entry.entry_attributes_as_dict.get("memberOf", [])
            admin_group_lower = admin_group.lower()
            for group_dn in member_of:
                if admin_group_lower in str(group_dn).lower():
                    is_admin = True
                    break
        except Exception:
            logger.warning("Could not check group membership for user '%s'", username)
    else:
        # If no admin group is configured, all LDAP users get admin
        is_admin = True

    user_info = {
        "username": username,
        "display_name": display_name or username,
        "email": email,
        "dn": user_dn,
        "is_admin": is_admin,
        "auth_source": "ldap",
    }

    logger.info("LDAP authentication successful for user '%s' (admin=%s)", username, is_admin)
    return user_info


async def authenticate_ldap(username: str, password: str) -> dict | None:
    """
    Authenticate a user against the configured LDAP server.

    Args:
        username: The username (sAMAccountName or equivalent).
        password: The user's password.

    Returns:
        A dict with user info (username, display_name, email, dn, is_admin,
        auth_source) on success, or None on failure.
    """
    if not username or not password:
        return None

    cfg = await _get_ldap_settings()

    enabled = cfg.get("ldap_enabled", "").lower()
    if enabled not in ("true", "1", "yes"):
        logger.debug("LDAP authentication is disabled")
        return None

    server_url = cfg.get("ldap_server_url", "")
    bind_dn = cfg.get("ldap_bind_dn", "")
    bind_password = cfg.get("ldap_bind_password", "")
    search_base = cfg.get("ldap_search_base", "")
    user_filter = cfg.get("ldap_user_filter", "") or DEFAULT_USER_FILTER
    admin_group = cfg.get("ldap_admin_group", "")
    use_ssl = cfg.get("ldap_use_ssl", "").lower() in ("true", "1", "yes")
    start_tls = cfg.get("ldap_start_tls", "").lower() in ("true", "1", "yes")
    display_name_attr = cfg.get("ldap_display_name_attr", "") or DEFAULT_DISPLAY_NAME_ATTR
    email_attr = cfg.get("ldap_email_attr", "") or DEFAULT_EMAIL_ATTR

    if not server_url or not bind_dn or not search_base:
        logger.error("LDAP configuration incomplete: server_url, bind_dn, or search_base missing")
        return None

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        _sync_authenticate,
        server_url,
        bind_dn,
        bind_password,
        search_base,
        user_filter,
        username,
        password,
        admin_group,
        use_ssl,
        start_tls,
        display_name_attr,
        email_attr,
    )

    return result


def _sync_test_connection(
    server_url: str,
    bind_dn: str,
    bind_password: str,
    search_base: str,
    use_ssl: bool = False,
    start_tls: bool = False,
) -> tuple[bool, str]:
    """Synchronous LDAP connection test (runs in thread executor)."""
    try:
        _, conn_kwargs = _build_ldap_connection(server_url, use_ssl, start_tls)

        conn = Connection(
            **conn_kwargs,
            user=bind_dn,
            password=bind_password,
        )

        if not conn.bind():
            desc = conn.result.get("description", "Bind failed")
            return False, f"LDAP bind failed: {desc}"

        if start_tls and not use_ssl:
            conn.start_tls()

        # Test search
        conn.search(
            search_base=search_base,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            size_limit=1,
        )

        entry_count = len(conn.entries)
        conn.unbind()

        return True, f"Connection successful. Found {entry_count} entry(ies) in search base."

    except LDAPSocketOpenError as exc:
        return False, f"Cannot connect to LDAP server: {exc}"
    except LDAPBindError as exc:
        return False, f"LDAP bind error: {exc}"
    except LDAPException as exc:
        return False, f"LDAP error: {exc}"
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


async def test_ldap_connection(ldap_settings: dict) -> tuple[bool, str]:
    """
    Test LDAP connection with the provided settings.

    Args:
        ldap_settings: Dict with keys: server_url, bind_dn, bind_password,
                      search_base, use_ssl, start_tls.

    Returns:
        Tuple of (success: bool, message: str).
    """
    server_url = ldap_settings.get("server_url", "")
    bind_dn = ldap_settings.get("bind_dn", "")
    bind_password = ldap_settings.get("bind_password", "")
    search_base = ldap_settings.get("search_base", "")
    use_ssl = ldap_settings.get("use_ssl", False)
    start_tls = ldap_settings.get("start_tls", False)

    if not server_url:
        return False, "LDAP server URL is required"
    if not bind_dn:
        return False, "Bind DN is required"
    if not search_base:
        return False, "Search base is required"

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        _sync_test_connection,
        server_url,
        bind_dn,
        bind_password,
        search_base,
        use_ssl,
        start_tls,
    )

    return result
