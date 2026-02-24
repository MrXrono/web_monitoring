from datetime import datetime

from sqlalchemy import Integer, BigInteger, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SmartHistory(Base):
    __tablename__ = "smart_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    physical_drive_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("physical_drives.id", ondelete="CASCADE"), nullable=False, index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    temperature: Mapped[int | None] = mapped_column(Integer)
    media_error_count: Mapped[int | None] = mapped_column(Integer)
    other_error_count: Mapped[int | None] = mapped_column(Integer)
    predictive_failure: Mapped[int | None] = mapped_column(Integer)
    reallocated_sectors: Mapped[int | None] = mapped_column(Integer)
    power_on_hours: Mapped[int | None] = mapped_column(Integer)
    smart_data: Mapped[dict | None] = mapped_column(JSONB)

    physical_drive = relationship("PhysicalDrive", back_populates="smart_history")
