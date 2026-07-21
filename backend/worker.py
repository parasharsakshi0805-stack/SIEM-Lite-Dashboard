import json
import time
from database import SessionLocal
from models import Log
from redis_client import redis_client

BATCH_SIZE = 50
FLUSH_INTERVAL = 5  # seconds

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
    finally:
        db.close()

if __name__ == "__main__":
    print("Worker started. Flushing every", FLUSH_INTERVAL, "seconds...")
    while True:
        flush_batch()
        time.sleep(FLUSH_INTERVAL)
