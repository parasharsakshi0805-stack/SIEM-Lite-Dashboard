import json
import time
from datetime import datetime
from database import SessionLocal
from models import Log, Anomaly
from redis_client import redis_client
from detector import SlidingWindowDetector

BATCH_SIZE = 50
FLUSH_INTERVAL = 5  # seconds

detector = SlidingWindowDetector(window_seconds=60, threshold=10)

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
    finally:
        db.close()

def check_anomalies(db, logs):
    anomalies_found = []
    for log in logs:
        result = detector.check_event(log["source_ip"])
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
        print(f"Flagged {len(anomalies_found)} anomalies")

if __name__ == "__main__":
    print("Worker started. Flushing every", FLUSH_INTERVAL, "seconds...")
    while True:
        flush_batch()
        time.sleep(FLUSH_INTERVAL)