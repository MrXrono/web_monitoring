import os
import sys
import secrets
import logging
import asyncio
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy import select, text

from app.config import settings
from app.database import engine, Base, async_session

logger = logging.getLogger("raid-monitor")


def setup_logging():
    level = logging.DEBUG if settings.DEBUG else getattr(logging, settings.LOG_LEVEL, logging.INFO)
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
    )

    # Also write logs to a file for debug page viewing / upload
    log_dir = Path(os.environ.get("LOG_DIR", "/app/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "server.log"
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    logging.getLogger().addHandler(file_handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def generate_env_file():
    """Generate .env file with random secrets on first start."""
    env_path = Path(settings.ENV_FILE_PATH)
    if env_path.exists():
        return

    admin_password = secrets.token_urlsafe(12)
    postgres_password = secrets.token_hex(32)
    secret_key = secrets.token_hex(32)
    encryption_key = secrets.token_hex(16)

    env_content = f"""# RAID Monitor - Auto-generated configuration
# Generated at: {datetime.now(timezone.utc).isoformat()}

POSTGRES_DB=raidmonitor
POSTGRES_USER=raidmonitor
POSTGRES_PASSWORD={postgres_password}

SECRET_KEY={secret_key}
ENCRYPTION_KEY={encryption_key}

ADMIN_PASSWORD={admin_password}
ADMIN_FORCE_ENABLE=false

TELEGRAM_BOT_TOKEN_ENCRYPTED=
TELEGRAM_CHAT_ID=

DEBUG=false
LOG_LEVEL=INFO
APP_HOST=0.0.0.0
APP_PORT=8000
"""
    try:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(env_content)
        logger.info("=" * 60)
        logger.info("FIRST START - Generated .env file")
        logger.info(f"Admin password: {admin_password}")
        logger.info("Save this password! It is also stored in .env file.")
        logger.info("=" * 60)
    except Exception as e:
        logger.error(f"Failed to generate .env: {e}")


def generate_self_signed_cert():
    """Generate self-signed SSL certificate if none exists."""
    cert_path = Path(settings.NGINX_SSL_DIR) / "server.crt"
    key_path = Path(settings.NGINX_SSL_DIR) / "server.key"

    if cert_path.exists() and key_path.exists():
        return

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "raid-monitor"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAID Monitor"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("raid-monitor"),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logger.info("Generated self-signed SSL certificate")
    except Exception as e:
        logger.error(f"Failed to generate SSL cert: {e}")


async def create_initial_admin():
    """Create initial admin user if not exists."""
    import bcrypt as _bcrypt
    from app.models.user import User

    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if result.scalar_one_or_none():
            return

        password = settings.ADMIN_PASSWORD or secrets.token_urlsafe(12)
        password_hash = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")
        admin = User(
            username="admin",
            password_hash=password_hash,
            display_name="Administrator",
            auth_source="local",
            is_active=True,
            is_admin=True,
            language="en",
        )
        db.add(admin)
        await db.commit()
        logger.info(f"Created initial admin user (password in .env file)")


async def seed_alert_rules():
    """Seed built-in alert rules."""
    try:
        from app.services.alert_engine import seed_builtin_rules
        async with async_session() as db:
            await seed_builtin_rules(db)
    except Exception as e:
        logger.error(f"Failed to seed alert rules: {e}")


async def seed_default_settings():
    """Seed default settings."""
    from app.models.setting import Setting

    defaults = [
        ("general.language", "en", False, "Default language", "general"),
        ("general.retention_days", "90", False, "Data retention in days", "general"),
        ("general.agent_auto_approve", "true", False, "Auto-approve new agents", "general"),
        ("ldap.enabled", "false", False, "LDAP authentication enabled", "ldap"),
        ("ldap.server_url", "", False, "LDAP server URL", "ldap"),
        ("ldap.bind_dn", "", False, "LDAP bind DN", "ldap"),
        ("ldap.bind_password", "", True, "LDAP bind password", "ldap"),
        ("ldap.search_base", "", False, "LDAP search base", "ldap"),
        ("ldap.user_filter", "(sAMAccountName={username})", False, "LDAP user filter", "ldap"),
        ("ldap.group_filter", "", False, "LDAP group filter", "ldap"),
        ("ldap.admin_group", "", False, "LDAP admin group DN", "ldap"),
        ("telegram.enabled", "false", False, "Telegram notifications enabled", "telegram"),
        ("telegram.bot_token", "", True, "Telegram bot token", "telegram"),
        ("telegram.chat_id", "", False, "Telegram chat ID", "telegram"),
        ("debug.web_enabled", "false", False, "Web debug logging", "debug"),
    ]

    async with async_session() as db:
        for key, value, encrypted, desc, category in defaults:
            result = await db.execute(select(Setting).where(Setting.key == key))
            if not result.scalar_one_or_none():
                s = Setting(key=key, value=value, is_encrypted=encrypted, description=desc, category=category)
                db.add(s)
        await db.commit()


async def migrate_add_columns():
    """Add new columns to existing tables (create_all doesn't ALTER existing tables)."""
    _columns = [
        # controllers
        ("controllers", "host_interface", "VARCHAR(32)"),
        ("controllers", "product_name", "VARCHAR(256)"),
        ("controllers", "supported_raid_levels", "JSONB"),
        ("controllers", "next_cc_launch", "VARCHAR(64)"),
        ("controllers", "next_pr_launch", "VARCHAR(64)"),
        ("controllers", "next_battery_learn", "VARCHAR(64)"),
        ("controllers", "ecc_bucket_count", "INTEGER DEFAULT 0"),
        ("controllers", "firmware_package_build", "VARCHAR(64)"),
        ("controllers", "driver_name", "VARCHAR(64)"),
        # virtual_drives
        ("virtual_drives", "active_operations", "VARCHAR(64)"),
        ("virtual_drives", "write_cache", "VARCHAR(64)"),
        ("virtual_drives", "span_depth", "INTEGER"),
        # physical_drives
        ("physical_drives", "link_speed", "VARCHAR(32)"),
        ("physical_drives", "device_speed", "VARCHAR(32)"),
        ("physical_drives", "physical_sector_size", "VARCHAR(16)"),
        ("physical_drives", "wwn", "VARCHAR(32)"),
        # bbu_units
        ("bbu_units", "capacitance", "VARCHAR(32)"),
        ("bbu_units", "pack_energy", "VARCHAR(32)"),
        ("bbu_units", "flash_size", "VARCHAR(32)"),
    ]
    async with engine.begin() as conn:
        for table, column, col_type in _columns:
            await conn.execute(
                text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type}")
            )
    logger.info("Database migration: checked %d columns", len(_columns))


async def register_prebuilt_packages():
    """Register pre-built agent RPM packages from /app/agent_packages/ into the database."""
    import hashlib
    import re as _re
    from app.models.agent_package import AgentPackage

    pkg_dir = Path("/app/agent_packages")
    if not pkg_dir.exists():
        return

    async with async_session() as db:
        for rpm_file in pkg_dir.glob("*.rpm"):
            # Check if already registered
            result = await db.execute(
                select(AgentPackage).where(AgentPackage.filename == rpm_file.name)
            )
            if result.scalar_one_or_none():
                continue

            data = rpm_file.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            version_match = _re.search(r"raid-agent-(\d+\.\d+\.\d+)", rpm_file.name)
            version = version_match.group(1) if version_match else "unknown"

            # Check if version already exists
            result = await db.execute(
                select(AgentPackage).where(AgentPackage.version == version)
            )
            if result.scalar_one_or_none():
                continue

            pkg = AgentPackage(
                version=version,
                filename=rpm_file.name,
                file_path=str(rpm_file),
                file_hash_sha256=sha256,
                file_size=rpm_file.stat().st_size,
                is_current=True,
            )
            db.add(pkg)
            logger.info("Registered pre-built agent package: %s (v%s)", rpm_file.name, version)

        await db.commit()


async def check_admin_expiry():
    """Disable local admin if force-enable expired."""
    from app.models.user import User

    async with async_session() as db:
        result = await db.execute(
            select(User).where(User.username == "admin", User.auth_source == "local")
        )
        admin = result.scalar_one_or_none()
        if admin and admin.local_admin_expires:
            if datetime.now(timezone.utc) > admin.local_admin_expires:
                admin.is_active = False
                admin.local_admin_expires = None
                await db.commit()
                logger.info("Local admin account expired and disabled")


async def start_scheduler():
    """Start background scheduler for periodic tasks."""
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    scheduler = AsyncIOScheduler()

    async def stale_check():
        from app.services.alert_engine import check_stale_agents
        try:
            async with async_session() as db:
                await check_stale_agents(db)
        except Exception as e:
            logger.error(f"Stale agent check error: {e}")

    async def admin_expiry_check():
        try:
            await check_admin_expiry()
        except Exception as e:
            logger.error(f"Admin expiry check error: {e}")

    scheduler.add_job(stale_check, "interval", minutes=5, id="stale_check")
    scheduler.add_job(admin_expiry_check, "interval", minutes=10, id="admin_expiry")
    scheduler.start()
    return scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Starting RAID Monitor Web Server...")

    generate_env_file()
    generate_self_signed_cert()

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Add new columns to existing tables (create_all doesn't ALTER)
    await migrate_add_columns()

    await create_initial_admin()
    await seed_default_settings()
    await seed_alert_rules()
    await register_prebuilt_packages()

    scheduler = await start_scheduler()

    logger.info("RAID Monitor Web Server started successfully")
    yield

    scheduler.shutdown()
    await engine.dispose()
    logger.info("RAID Monitor Web Server stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="RAID Monitor",
        description="RAID Controller Monitoring System",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
    )

    # Static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # API routes
    from app.api.v1 import agent as agent_api
    from app.api.v1 import auth as auth_api
    from app.api.v1 import servers as servers_api
    from app.api.v1 import alerts as alerts_api
    from app.api.v1 import settings as settings_api
    from app.api.v1 import dashboard as dashboard_api

    app.include_router(agent_api.router, prefix="/api/v1/agent", tags=["agent"])
    app.include_router(auth_api.router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(servers_api.router, prefix="/api/v1/servers", tags=["servers"])
    app.include_router(alerts_api.router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(settings_api.router, prefix="/api/v1/settings", tags=["settings"])
    app.include_router(dashboard_api.router, prefix="/api/v1/dashboard", tags=["dashboard"])

    # Web routes
    from app.web.routes import router as web_router
    app.include_router(web_router)

    return app


app = create_app()

if __name__ == "__main__":
    setup_logging()
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.DEBUG,
        reload_excludes=["*.log", "logs/*"] if settings.DEBUG else None,
        log_level=settings.LOG_LEVEL.lower(),
    )
