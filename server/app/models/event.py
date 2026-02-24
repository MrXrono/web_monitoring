from datetime import datetime

from sqlalchemy import String, Integer, BigInteger, Text, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ControllerEvent(Base):
    __tablename__ = "controller_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    controller_id: Mapped[str] = mapped_column(UUID(as_uuid=True), ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id: Mapped[int | None] = mapped_column(Integer)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    event_class: Mapped[str | None] = mapped_column(String(64))
    event_description: Mapped[str | None] = mapped_column(Text)
    event_data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    controller = relationship("Controller", back_populates="events")
