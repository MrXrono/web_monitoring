import os
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    POSTGRES_DB: str = "raidmonitor"
    POSTGRES_USER: str = "raidmonitor"
    POSTGRES_PASSWORD: str = "changeme"
    DATABASE_URL: str = ""

    # App
    SECRET_KEY: str = secrets.token_hex(32)
    ENCRYPTION_KEY: str = secrets.token_hex(16)
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # Admin
    ADMIN_PASSWORD: str = ""
    ADMIN_FORCE_ENABLE: str = "false"

    # Telegram
    TELEGRAM_BOT_TOKEN_ENCRYPTED: str = ""
    TELEGRAM_CHAT_ID: str = ""

    # Paths
    BASE_DIR: str = str(Path(__file__).resolve().parent.parent)
    STORCLI_PACKAGES_DIR: str = "/app/storcli_packages"
    AGENT_PACKAGES_DIR: str = "/app/agent_packages"
    UPLOADS_DIR: str = "/app/uploads"
    NGINX_SSL_DIR: str = "/app/nginx_ssl"
    ENV_FILE_PATH: str = "/app/.env"

    # File upload server
    FILE_UPLOAD_URL: str = "https://private-ai.tools/upload"
    FILE_DOWNLOAD_BASE: str = "https://private-ai.tools/files"

    @property
    def database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@postgres:5432/{self.POSTGRES_DB}"
        )

    @property
    def database_url_sync(self) -> str:
        return self.database_url.replace("+asyncpg", "")

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
