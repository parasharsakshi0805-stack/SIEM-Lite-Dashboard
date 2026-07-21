from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import json

from database import SessionLocal, engine, Base
from models import Log
from schemas import LogCreate, LogResponse
from redis_client import redis_client

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SIEM-lite Dashboard API")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/logs/ingest")
def ingest_log(log: LogCreate):
    redis_client.rpush("log_queue", json.dumps(log.model_dump()))
    return {"status": "queued"}

@app.post("/logs/ingest/batch")
def ingest_logs_batch(logs: List[LogCreate]):
    pipe = redis_client.pipeline()
    for log in logs:
        pipe.rpush("log_queue", json.dumps(log.model_dump()))
    pipe.execute()
    return {"status": "queued", "count": len(logs)}

@app.get("/logs", response_model=List[LogResponse])
def get_logs(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Log)
    if severity:
        query = query.filter(Log.severity == severity)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    logs = query.order_by(desc(Log.timestamp)).offset(skip).limit(limit).all()
    return logs
