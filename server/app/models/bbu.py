import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class BbuUnit(Base):
    __tablename__ = "bbu_units"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    controller_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("controllers.id", ondelete="CASCADE"), unique=True)
    bbu_type: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[str | None] = mapped_column(String(64))
    voltage: Mapped[str | None] = mapped_column(String(32))
    temperature: Mapped[int | None] = mapped_column(Integer)
    learn_cycle_status: Mapped[str | None] = mapped_column(String(64))
    next_learn_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    manufacture_date: Mapped[str | None] = mapped_column(String(32))
    design_capacity: Mapped[str | None] = mapped_column(String(32))
    remaining_capacity: Mapped[str | None] = mapped_column(String(32))
    replacement_needed: Mapped[bool] = mapped_column(Boolean, default=False)
    capacitance: Mapped[str | None] = mapped_column(String(32))
    pack_energy: Mapped[str | None] = mapped_column(String(32))
    flash_size: Mapped[str | None] = mapped_column(String(32))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    controller = relationship("Controller", back_populates="bbu")
