import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SoftwareRaid(Base):
    __tablename__ = "software_raids"
    __table_args__ = (
        UniqueConstraint("server_id", "array_name", name="uq_swraid_server_array"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True)
    array_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raid_level: Mapped[str | None] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    array_size: Mapped[str | None] = mapped_column(String(64))
    num_devices: Mapped[int | None] = mapped_column(Integer)
    active_devices: Mapped[int | None] = mapped_column(Integer)
    working_devices: Mapped[int | None] = mapped_column(Integer)
    failed_devices: Mapped[int | None] = mapped_column(Integer)
    spare_devices: Mapped[int | None] = mapped_column(Integer)
    rebuild_progress: Mapped[float | None] = mapped_column(Float)
    uuid_str: Mapped[str | None] = mapped_column(String(128))
    creation_time: Mapped[str | None] = mapped_column(String(64))
    member_devices: Mapped[dict | None] = mapped_column(JSONB)
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    server = relationship("Server", back_populates="software_raids")
