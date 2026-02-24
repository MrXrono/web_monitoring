import uuid
from datetime import datetime

from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class VirtualDrive(Base):
    __tablename__ = "virtual_drives"
    __table_args__ = (UniqueConstraint("controller_id", "vd_id", name="uq_vd_controller"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    controller_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False)
    vd_id: Mapped[int] = mapped_column(Integer, nullable=False)
    dg_id: Mapped[int | None] = mapped_column(Integer)
    name: Mapped[str | None] = mapped_column(String(256))
    raid_type: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size: Mapped[str | None] = mapped_column(String(32))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    strip_size: Mapped[str | None] = mapped_column(String(16))
    number_of_drives: Mapped[int | None] = mapped_column(Integer)
    cache_policy: Mapped[str | None] = mapped_column(String(64))
    io_policy: Mapped[str | None] = mapped_column(String(32))
    read_policy: Mapped[str | None] = mapped_column(String(32))
    disk_cache_policy: Mapped[str | None] = mapped_column(String(32))
    consistent: Mapped[bool | None] = mapped_column(Boolean)
    access: Mapped[str | None] = mapped_column(String(32))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    controller = relationship("Controller", back_populates="virtual_drives")
