import uuid
from datetime import datetime

from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Controller(Base):
    __tablename__ = "controllers"
    __table_args__ = (UniqueConstraint("server_id", "controller_id", name="uq_controller_server"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    controller_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model: Mapped[str | None] = mapped_column(String(256))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    firmware_version: Mapped[str | None] = mapped_column(String(64))
    bios_version: Mapped[str | None] = mapped_column(String(64))
    driver_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str | None] = mapped_column(String(64))
    memory_size: Mapped[str | None] = mapped_column(String(32))
    memory_correctable_errors: Mapped[int] = mapped_column(Integer, default=0)
    memory_uncorrectable_errors: Mapped[int] = mapped_column(Integer, default=0)
    roc_temperature: Mapped[int | None] = mapped_column(Integer)
    rebuild_rate: Mapped[int | None] = mapped_column(Integer)
    patrol_read_status: Mapped[str | None] = mapped_column(String(64))
    cc_status: Mapped[str | None] = mapped_column(String(64))
    alarm_status: Mapped[str | None] = mapped_column(String(32))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    server = relationship("Server", back_populates="controllers")
    bbu = relationship("BbuUnit", back_populates="controller", uselist=False, cascade="all, delete-orphan")
    virtual_drives = relationship("VirtualDrive", back_populates="controller", cascade="all, delete-orphan")
    physical_drives = relationship("PhysicalDrive", back_populates="controller", cascade="all, delete-orphan")
    events = relationship("ControllerEvent", back_populates="controller", cascade="all, delete-orphan")
