from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    raw_message = Column(Text)
    tenant_id = Column(String, index=True, default="default")
