from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from datetime import datetime
import json

from database import SessionLocal, engine, Base
from models import Log
from schemas import LogCreate, LogResponse
from redis_client import redis_client
from fastapi.middleware.cors import CORSMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SIEM-lite Dashboard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
from sqlalchemy import func

@app.get("/logs/stats")
def get_logs_stats(db: Session = Depends(get_db)):
    severity_counts = (
        db.query(Log.severity, func.count(Log.id))
        .group_by(Log.severity)
        .all()
    )

    event_type_counts = (
        db.query(Log.event_type, func.count(Log.id))
        .group_by(Log.event_type)
        .all()
    )

    top_ips = (
        db.query(Log.source_ip, func.count(Log.id).label("count"))
        .group_by(Log.source_ip)
        .order_by(func.count(Log.id).desc())
        .limit(10)
        .all()
    )

    return {
        "severity_breakdown": [{"severity": s, "count": c} for s, c in severity_counts],
        "event_type_breakdown": [{"event_type": e, "count": c} for e, c in event_type_counts],
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
    }