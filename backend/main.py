from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from datetime import datetime
import json

from database import SessionLocal, engine, Base
from schemas import LogCreate, LogResponse
from redis_client import redis_client
from fastapi.middleware.cors import CORSMiddleware
from models import Log, Anomaly

import os

app = FastAPI(title="SIEM-lite Dashboard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
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

from fastapi import HTTPException

@app.post("/logs/ingest")
def ingest_log(log: LogCreate):
    try:
        redis_client.rpush("log_queue", json.dumps(log.model_dump()))
        return {"status": "queued"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to queue log: {str(e)}")

@app.post("/logs/ingest/batch")
def ingest_logs_batch(logs: List[LogCreate]):
    try:
        pipe = redis_client.pipeline()
        for log in logs:
            pipe.rpush("log_queue", json.dumps(log.model_dump()))
        pipe.execute()
        return {"status": "queued", "count": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to queue logs: {str(e)}")

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

@app.get("/anomalies")
def get_anomalies(limit: int = 50, db: Session = Depends(get_db)):
    anomalies = db.query(Anomaly).order_by(desc(Anomaly.timestamp)).limit(limit).all()
    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "reason": a.reason,
            "score": a.score,
            "source": a.source,
            "timestamp": a.timestamp,
        }
        for a in anomalies
    ]