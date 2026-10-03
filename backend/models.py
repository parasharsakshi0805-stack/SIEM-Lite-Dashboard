from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
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
    # CHANGED: indexed, and now holds the time the event HAPPENED (sent by the
    # agent), not the time the server received it. Falls back to "now" if missing.
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    raw_message = Column(Text)
    tenant_id = Column(String, index=True, default="default")
    # NEW: WHO and WHERE. Without these you cannot tell "5 failures then a
    # success as 'deploy'" from random noise.
    username = Column(String, index=True, nullable=True)
    host = Column(String, index=True, nullable=True)
    # NEW: "success" / "failure" / NULL (not a login result). Rules key off this.
    outcome = Column(String, index=True, nullable=True)

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, index=True)   # now filled in with the real triggering log
    source_ip = Column(String, index=True)
    reason = Column(String)
    score = Column(Integer)
    source = Column(String, default="sliding_window")
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    # NEW: how bad is it ("low" / "medium" / "high" / "critical").
    severity = Column(String, index=True, default="medium")
    # NEW: the evidence behind the alert (counts, usernames, times, next steps)
    # as structured data, so the UI can render a story instead of one sentence.
    details = Column(JSON, nullable=True)
