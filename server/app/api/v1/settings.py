import hashlib
import logging
import shutil
from datetime import datetime
from app.config import MSK
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as app_settings
from app.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.setting import Setting
from app.models.server import Server
from app.models.agent_package import AgentPackage
from app.services.encryption import encrypt_value, decrypt_value
from app.schemas.settings import (
    SettingItem,
    SettingsCategoryResponse,
    SettingsUpdateRequest,
    SettingsUpdateResponse,
    SSLUploadResponse,
    LdapTestRequest,
    LdapTestResponse,
    TelegramTestRequest,
    TelegramTestResponse,
    AgentPackageResponse,
    LogCollectResponse,
    LogUploadExternalResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])

# Keys whose values must be stored encrypted
ENCRYPTED_KEYS = {
    "ldap_bind_password",
    "telegram_bot_token",
    "smtp_password",
}


def _require_admin(user: User):
    """Raise 403 if user is not an admin."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )


@router.get("/{category}", response_model=SettingsCategoryResponse)
async def get_settings(
    category: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all settings for a given category."""
    result = await db.execute(
        select(Setting).where(Setting.category == category).order_by(Setting.key.asc())
    )
    db_settings = result.scalars().all()

    items = []
    for s in db_settings:
        value = s.value
        # Mask encrypted values for display
        if s.is_encrypted and value:
            value = "********"

        items.append(SettingItem(
            key=s.key,
            value=value,
            is_encrypted=s.is_encrypted,
            description=s.description,
            category=s.category,
            updated_at=s.updated_at,
        ))

    return SettingsCategoryResponse(
        category=category,
        settings=items,
    )


@router.put("/{category}", response_model=SettingsUpdateResponse)
async def update_settings(
    category: str,
    payload: SettingsUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update settings for a given category."""
    _require_admin(user)

    updated_keys = []

    for key, value in payload.settings.items():
        result = await db.execute(
            select(Setting).where(Setting.key == key, Setting.category == category)
        )
        setting = result.scalar_one_or_none()

        if setting is None:
            # Create new setting
            setting = Setting(
                key=key,
                category=category,
            )
            db.add(setting)

        # Encrypt if needed
        if key in ENCRYPTED_KEYS and value:
            setting.value = encrypt_value(value)
            setting.is_encrypted = True
        else:
            setting.value = value
            setting.is_encrypted = False

        updated_keys.append(key)

    await db.commit()

    return SettingsUpdateResponse(
        updated=updated_keys,
        message=f"Updated {len(updated_keys)} setting(s) in category '{category}'",
    )


@router.post("/ssl/upload", response_model=SSLUploadResponse)
async def upload_ssl_cert(
    cert_file: UploadFile = File(None),
    key_file: UploadFile = File(None),
    user: User = Depends(get_current_user),
):
    """Upload SSL certificate and/or key files for NGINX."""
    _require_admin(user)

    ssl_dir = Path(app_settings.NGINX_SSL_DIR)
    ssl_dir.mkdir(parents=True, exist_ok=True)

    cert_filename = None
    key_filename = None

    if cert_file:
        cert_content = await cert_file.read()
        cert_path = ssl_dir / "server.crt"
        with open(cert_path, "wb") as f:
            f.write(cert_content)
        cert_filename = "server.crt"
        logger.info("SSL certificate uploaded: %d bytes", len(cert_content))

    if key_file:
        key_content = await key_file.read()
        key_path = ssl_dir / "server.key"
        with open(key_path, "wb") as f:
            f.write(key_content)
        key_filename = "server.key"
        logger.info("SSL key uploaded: %d bytes", len(key_content))

    if not cert_filename and not key_filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one file (cert_file or key_file) must be provided",
        )

    return SSLUploadResponse(
        message="SSL files uploaded successfully",
        cert_filename=cert_filename,
        key_filename=key_filename,
    )


@router.post("/ldap/test", response_model=LdapTestResponse)
async def test_ldap(
    payload: LdapTestRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Test LDAP connection and optionally a user bind."""
    _require_admin(user)

    try:
        import ldap3
    except ImportError:
        return LdapTestResponse(
            success=False,
            message="ldap3 library is not installed on the server",
        )

    # Get LDAP settings from DB or from the request payload
    server_url = payload.server_url
    bind_dn = payload.bind_dn
    bind_password = payload.bind_password
    search_base = payload.search_base

    # Fall back to DB settings if not provided in payload
    if not server_url or not bind_dn or not search_base:
        ldap_keys = ["ldap_server_url", "ldap_bind_dn", "ldap_bind_password", "ldap_search_base"]
        result = await db.execute(select(Setting).where(Setting.key.in_(ldap_keys)))
        db_ldap = {s.key: s for s in result.scalars().all()}

        if not server_url and "ldap_server_url" in db_ldap:
            server_url = db_ldap["ldap_server_url"].value
        if not bind_dn and "ldap_bind_dn" in db_ldap:
            bind_dn = db_ldap["ldap_bind_dn"].value
        if not bind_password and "ldap_bind_password" in db_ldap:
            bp_setting = db_ldap["ldap_bind_password"]
            if bp_setting.is_encrypted and bp_setting.value:
                bind_password = decrypt_value(bp_setting.value)
            else:
                bind_password = bp_setting.value
        if not search_base and "ldap_search_base" in db_ldap:
            search_base = db_ldap["ldap_search_base"].value

    if not server_url:
        return LdapTestResponse(success=False, message="LDAP server URL not configured")

    try:
        server = ldap3.Server(server_url, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password or "", auto_bind=True)

        # If test user credentials provided, try user search + bind
        user_dn = None
        if payload.username and payload.password:
            user_filter = f"(sAMAccountName={payload.username})"
            conn.search(search_base or "", user_filter, search_scope=ldap3.SUBTREE)

            if not conn.entries:
                conn.unbind()
                return LdapTestResponse(
                    success=False,
                    message=f"User '{payload.username}' not found in LDAP",
                )

            user_dn = conn.entries[0].entry_dn
            user_conn = ldap3.Connection(server, user=user_dn, password=payload.password, auto_bind=True)
            user_conn.unbind()

        conn.unbind()

        return LdapTestResponse(
            success=True,
            message="LDAP connection successful" + (f", user bind OK for {user_dn}" if user_dn else ""),
            user_dn=user_dn,
        )

    except ldap3.core.exceptions.LDAPBindError as e:
        return LdapTestResponse(success=False, message=f"LDAP bind failed: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        return LdapTestResponse(success=False, message=f"Cannot connect to LDAP server: {e}")
    except Exception as e:
        return LdapTestResponse(success=False, message=f"LDAP test error: {e}")


@router.post("/telegram/test", response_model=TelegramTestResponse)
async def test_telegram(
    payload: TelegramTestRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Test Telegram bot notification by sending a test message."""
    _require_admin(user)

    import httpx

    bot_token = payload.bot_token
    chat_id = payload.chat_id

    # Fall back to DB settings if not provided
    if not bot_token or not chat_id:
        tg_keys = ["telegram_bot_token", "telegram_chat_id"]
        result = await db.execute(select(Setting).where(Setting.key.in_(tg_keys)))
        tg_settings = {s.key: s for s in result.scalars().all()}

        if not bot_token and "telegram_bot_token" in tg_settings:
            token_setting = tg_settings["telegram_bot_token"]
            if token_setting.is_encrypted and token_setting.value:
                bot_token = decrypt_value(token_setting.value)
            else:
                bot_token = token_setting.value
        if not chat_id and "telegram_chat_id" in tg_settings:
            chat_id = tg_settings["telegram_chat_id"].value

    if not bot_token:
        return TelegramTestResponse(success=False, message="Telegram bot token not configured")
    if not chat_id:
        return TelegramTestResponse(success=False, message="Telegram chat ID not configured")

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id,
                "text": payload.message,
                "parse_mode": "HTML",
            })

        if resp.status_code == 200 and resp.json().get("ok"):
            return TelegramTestResponse(success=True, message="Test message sent successfully")
        else:
            error_desc = resp.json().get("description", resp.text)
            return TelegramTestResponse(success=False, message=f"Telegram API error: {error_desc}")

    except httpx.TimeoutException:
        return TelegramTestResponse(success=False, message="Telegram API request timed out")
    except Exception as e:
        return TelegramTestResponse(success=False, message=f"Failed to send: {e}")


@router.post("/agents/upload", response_model=AgentPackageResponse)
async def upload_agent_package(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a new agent RPM package."""
    _require_admin(user)

    if not file.filename or not file.filename.endswith(".rpm"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .rpm files are accepted",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file",
        )

    # Compute SHA256
    sha256 = hashlib.sha256(content).hexdigest()

    # Extract version from filename (convention: raid-monitor-agent-X.Y.Z-N.el9.x86_64.rpm)
    filename = file.filename
    version = "unknown"
    parts = filename.replace(".rpm", "").split("-")
    # Try to find version-like string
    for i, part in enumerate(parts):
        if part and part[0].isdigit():
            version = "-".join(parts[i:])
            break

    # Save file
    pkg_dir = Path(app_settings.AGENT_PACKAGES_DIR)
    pkg_dir.mkdir(parents=True, exist_ok=True)
    file_path = pkg_dir / filename

    with open(file_path, "wb") as f:
        f.write(content)

    # Mark all existing packages as not current
    result = await db.execute(select(AgentPackage).where(AgentPackage.is_current.is_(True)))
    for pkg in result.scalars().all():
        pkg.is_current = False

    # Create new package record
    package = AgentPackage(
        version=version,
        filename=filename,
        file_path=str(file_path),
        file_hash_sha256=sha256,
        file_size=len(content),
        is_current=True,
    )
    db.add(package)
    await db.commit()
    await db.refresh(package)

    return AgentPackageResponse(
        id=str(package.id),
        version=package.version,
        filename=package.filename,
        file_hash_sha256=package.file_hash_sha256,
        file_size=package.file_size,
        release_notes=package.release_notes,
        is_current=package.is_current,
        uploaded_at=package.uploaded_at,
    )


@router.post("/logs/collect-all", response_model=LogCollectResponse)
async def collect_all_logs(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Request log collection from all online agents."""
    _require_admin(user)

    import secrets as secrets_mod

    result = await db.execute(
        select(Server).where(Server.status == "online")
    )
    servers = result.scalars().all()

    count = 0
    for srv in servers:
        cmd_id = secrets_mod.token_hex(8)
        command = {
            "id": cmd_id,
            "type": "collect_logs",
            "created_at": datetime.now(MSK).isoformat(),
        }
        server_info = srv.server_info or {}
        pending = server_info.get("pending_commands", [])
        pending.append(command)
        server_info["pending_commands"] = pending
        srv.server_info = server_info
        count += 1

    await db.commit()

    return LogCollectResponse(
        message=f"Log collection requested from {count} server(s)",
        servers_count=count,
    )


@router.post("/logs/upload-external", response_model=LogUploadExternalResponse)
async def upload_logs_external(
    user: User = Depends(get_current_user),
):
    """
    Collect all saved agent logs and upload them to the external file server.
    """
    _require_admin(user)

    import httpx
    import tempfile
    import tarfile

    logs_dir = Path(app_settings.UPLOADS_DIR) / "agent_logs"
    if not logs_dir.exists() or not any(logs_dir.iterdir()):
        return LogUploadExternalResponse(
            success=False,
            message="No agent logs found to upload",
        )

    # Create tar.gz archive of all logs
    timestamp = datetime.now(MSK).strftime("%Y%m%d_%H%M%S")
    archive_name = f"agent_logs_{timestamp}.tar.gz"

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        with tarfile.open(tmp_path, "w:gz") as tar:
            tar.add(str(logs_dir), arcname="agent_logs")

        # Upload to file server
        async with httpx.AsyncClient(timeout=120, verify=False) as client:
            with open(tmp_path, "rb") as f:
                resp = await client.post(
                    app_settings.FILE_UPLOAD_URL,
                    files={"file": (archive_name, f, "application/gzip")},
                )

        if resp.status_code == 200:
            download_url = f"{app_settings.FILE_DOWNLOAD_BASE}/{archive_name}"
            return LogUploadExternalResponse(
                success=True,
                message="Logs uploaded successfully",
                url=download_url,
            )
        else:
            return LogUploadExternalResponse(
                success=False,
                message=f"Upload failed with status {resp.status_code}: {resp.text}",
            )

    except Exception as e:
        logger.exception("Failed to upload logs externally")
        return LogUploadExternalResponse(
            success=False,
            message=f"Upload failed: {e}",
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)
