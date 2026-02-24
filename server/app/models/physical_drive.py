import uuid
from datetime import datetime

from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PhysicalDrive(Base):
    __tablename__ = "physical_drives"
    __table_args__ = (UniqueConstraint("controller_id", "enclosure_id", "slot_number", name="uq_pd_controller"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    controller_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False)
    enclosure_id: Mapped[int] = mapped_column(Integer, nullable=False)
    slot_number: Mapped[int] = mapped_column(Integer, nullable=False)
    device_id: Mapped[int | None] = mapped_column(Integer)
    drive_group: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size: Mapped[str | None] = mapped_column(String(32))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    media_type: Mapped[str | None] = mapped_column(String(16))
    interface_type: Mapped[str | None] = mapped_column(String(16))
    model: Mapped[str | None] = mapped_column(String(256))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    firmware_version: Mapped[str | None] = mapped_column(String(64))
    manufacturer: Mapped[str | None] = mapped_column(String(128))
    sector_size: Mapped[str | None] = mapped_column(String(16))
    rotation_speed: Mapped[str | None] = mapped_column(String(16))
    temperature: Mapped[int | None] = mapped_column(Integer)
    shield_counter: Mapped[int] = mapped_column(Integer, default=0)
    media_error_count: Mapped[int] = mapped_column(Integer, default=0)
    other_error_count: Mapped[int] = mapped_column(Integer, default=0)
    predictive_failure: Mapped[int] = mapped_column(Integer, default=0)
    smart_alert: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    smart_data: Mapped[dict | None] = mapped_column(JSONB)
    pd_raw_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    controller = relationship("Controller", back_populates="physical_drives")
    smart_history = relationship("SmartHistory", back_populates="physical_drive", cascade="all, delete-orphan")
