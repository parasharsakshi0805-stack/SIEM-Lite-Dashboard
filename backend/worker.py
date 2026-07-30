import json
import time
import pandas as pd
import joblib
import os
from datetime import datetime
from database import SessionLocal
from models import Log, Anomaly
from redis_client import redis_client
from detector import SlidingWindowDetector
from ml_features import extract_features

BATCH_SIZE = 50
FLUSH_INTERVAL = 5  # seconds
MODEL_PATH = "isolation_forest_model.joblib"

detector = SlidingWindowDetector(window_seconds=60, threshold=10)

ml_model = None
if os.path.exists(MODEL_PATH):
    ml_model = joblib.load(MODEL_PATH)
    print("ML model loaded.")
else:
    print("WARNING: No ML model found. Run train_model.py first. ML scoring disabled.")

def flush_batch():
    db = SessionLocal()
    try:
        logs_to_insert = []
        for _ in range(BATCH_SIZE):
            item = redis_client.lpop("log_queue")
            if item is None:
                break
            logs_to_insert.append(json.loads(item))

        if logs_to_insert:
            db.bulk_insert_mappings(Log, logs_to_insert)
            db.commit()
            print(f"Flushed {len(logs_to_insert)} logs to Postgres")

            check_anomalies(db, logs_to_insert)
            if ml_model is not None:
                check_ml_anomalies(db, logs_to_insert)
    finally:
        db.close()

def check_anomalies(db, logs):
    anomalies_found = []
    for log in logs:
        event_time = datetime.fromisoformat(log["timestamp"]) if "timestamp" in log else datetime.utcnow()
        # If timestamp is naive or aware, fromisoformat handles it in 3.11+. 
        # But to be safe if 'Z' is used, replace 'Z' with '+00:00'
        if isinstance(log.get("timestamp"), str) and log["timestamp"].endswith("Z"):
            event_time = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
        
        result = detector.check_event(log["source_ip"], event_time=event_time)
        if result["is_anomaly"]:
            anomalies_found.append({
                "log_id": None,
                "source_ip": log["source_ip"],
                "reason": f"{result['count']} events in {detector.window_seconds}s window (threshold {result['threshold']})",
                "score": result["count"],
                "source": "sliding_window",
            })

    if anomalies_found:
        db.bulk_insert_mappings(Anomaly, anomalies_found)
        db.commit()
        print(f"Flagged {len(anomalies_found)} sliding-window anomalies")

def check_ml_anomalies(db, logs):
    df = pd.DataFrame(logs)
    df["id"] = range(len(df))  # dummy id for grouping within this batch
    df["timestamp"] = pd.Timestamp.utcnow()

    features = extract_features(df)
    predictions = ml_model.predict(features)  # -1 = anomaly, 1 = normal
    scores = ml_model.decision_function(features)  # lower = more anomalous

    anomalies_found = []
    for i, pred in enumerate(predictions):
        if pred == -1:
            anomalies_found.append({
                "log_id": None,
                "source_ip": logs[i]["source_ip"],
                "reason": "Flagged by Isolation Forest (unusual pattern)",
                "score": int(scores[i] * -100),  # scaled for readability
                "source": "ml",
            })

    if anomalies_found:
        db.bulk_insert_mappings(Anomaly, anomalies_found)
        db.commit()
        print(f"Flagged {len(anomalies_found)} ML anomalies")

if __name__ == "__main__":
    print("Worker started. Flushing every", FLUSH_INTERVAL, "seconds...")
    while True:
        flush_batch()
        time.sleep(FLUSH_INTERVAL)