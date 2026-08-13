from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    raw_message = Column(Text)
    tenant_id = Column(String, index=True, default="default")

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, index=True)
    source_ip = Column(String, index=True)
    reason = Column(String)
    score = Column(Integer)
    source = Column(String, default="sliding_window")
    timestamp = Column(DateTime(timezone=True), server_default=func.now())