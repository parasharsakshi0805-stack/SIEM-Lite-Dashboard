from fastapi import FastAPI, Depends, Query, HTTPException, Request , Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional
from datetime import datetime, timedelta
import json

from database import SessionLocal, engine, Base, get_db
from schemas import LogCreate, LogResponse, Token, UserOut
from redis_client import redis_client
from fastapi.middleware.cors import CORSMiddleware
from models import Log, Anomaly, User
from auth import authenticate_user, create_access_token, get_current_user

import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI(title="SIEM-lite Dashboard API")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": user.username})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        max_age=60 * 60 * 8,
        path="/",
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"status": "logged out"}


@app.get("/auth/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/logs/ingest")
def ingest_log(log: LogCreate, current_user: User = Depends(get_current_user)):
    try:
        redis_client.rpush("log_queue", json.dumps(log.model_dump()))
        return {"status": "queued"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to queue log: {str(e)}")

@app.post("/logs/ingest/batch")
def ingest_logs_batch(logs: List[LogCreate], current_user: User = Depends(get_current_user)):
    if len(logs) > 1000:
        raise HTTPException(
            status_code=413,
            detail="Batch too large. Maximum 1000 logs per request.",
        )
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
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Log)
    if severity:
        query = query.filter(Log.severity == severity)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    logs = query.order_by(desc(Log.timestamp)).offset(skip).limit(limit).all()
    return logs


@app.get("/logs/stats")
@app.get("/logs/stats")
def get_logs_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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

    total_logs = db.query(func.count(Log.id)).scalar()
    total_anomalies = db.query(func.count(Anomaly.id)).scalar()
    critical_count = db.query(func.count(Log.id)).filter(Log.severity == "critical").scalar()
    unique_ips = db.query(func.count(func.distinct(Log.source_ip))).scalar()

    return {
        "severity_breakdown": [{"severity": s, "count": c} for s, c in severity_counts],
        "event_type_breakdown": [{"event_type": e, "count": c} for e, c in event_type_counts],
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "summary": {
            "total_logs": total_logs,
            "total_anomalies": total_anomalies,
            "critical_count": critical_count,
            "unique_ips": unique_ips,
        },
    }

@app.get("/logs/stats/timeline")
def get_logs_timeline(hours: int = Query(default=24, ge=1, le=168), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    since = datetime.utcnow() - timedelta(hours=hours)
    results = (
        db.query(
            func.date_trunc('hour', Log.timestamp).label('hour'),
            func.count(Log.id).label('count')
        )
        .filter(Log.timestamp >= since)
        .group_by('hour')
        .order_by('hour')
        .all()
    )
    return [{"hour": r.hour.isoformat(), "count": r.count} for r in results]

@app.get("/anomalies")
def get_anomalies(limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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