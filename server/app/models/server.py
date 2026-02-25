import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, DateTime, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(512))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))
    kernel_version: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    storcli_version: Mapped[str | None] = mapped_column(String(32))
    cpu_model: Mapped[str | None] = mapped_column(String(256))
    cpu_cores: Mapped[int | None] = mapped_column()
    ram_total_gb: Mapped[float | None] = mapped_column()
    uptime_seconds: Mapped[int | None] = mapped_column()
    last_os_update: Mapped[str | None] = mapped_column(String(128))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_report: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSONB))
    server_info: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSONB))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    debug_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    api_key = relationship("ApiKey", back_populates="server", uselist=False, cascade="all, delete-orphan")
    controllers = relationship("Controller", back_populates="server", cascade="all, delete-orphan")
    alert_history = relationship("AlertHistory", back_populates="server", cascade="all, delete-orphan")
