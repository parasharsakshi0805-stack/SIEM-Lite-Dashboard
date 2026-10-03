"""
worker.py -- the background process that turns queued logs into stored logs + alerts.

Life of a log, step by step:
  1. API puts it in the Redis stream.
  2. This worker reads a batch (it stays "pending" in Redis, not deleted).
  3. Saves the batch to Postgres.
  4. Runs three detectors: sliding window, rules (compromise/spray), ML.
  5. Saves any alerts and COMMITS (logs and alerts together, or neither).
  6. Only now tells Redis "ACK, done" -- and deletes the entries.
If the worker dies between 2 and 6, the batch is still pending and is retried.

IMPORTANT: run exactly ONE worker. The detectors keep their memory inside this
process, so a second worker would only see half of each IP's events.
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import joblib
import pandas as pd

import log_queue as q
from database import SessionLocal
from detector import SlidingWindowDetector
from ml_features import FEATURE_COLUMNS, build_features
from models import Anomaly, Log
from redis_client import redis_client
from rules import Event, RuleEngine

BATCH_SIZE = 50
BLOCK_MS = 1000                       # how long to wait for new logs before looping again
MAX_RETRIES = 5                       # a batch that fails this many times goes to the dead stream
CONSUMER = os.getenv("WORKER_NAME", "worker-1")   # must stay the same across restarts
MODEL_PATH = "isolation_forest_model.joblib"
MAX_FUTURE_SKEW = timedelta(minutes=5)

LOG_FIELDS = ("source_ip", "event_type", "severity", "raw_message",
              "tenant_id", "username", "host", "outcome")

detector = SlidingWindowDetector(window_seconds=60, threshold=10)
rule_engine = RuleEngine()


def load_model():
    """Load the ML model only if it was trained with the SAME features we compute now."""
    if not os.path.exists(MODEL_PATH):
        print("WARNING: No ML model found. Run train_model.py first. ML scoring disabled.")
        return None
    bundle = joblib.load(MODEL_PATH)
    if not isinstance(bundle, dict) or bundle.get("features") != FEATURE_COLUMNS:
        print("WARNING: ML model is from an older version (different features). "
              "Run train_model.py again. ML scoring disabled.")
        return None
    print(f"ML model loaded (trained {bundle['trained_at']} on {bundle['rows']} rows).")
    return bundle["model"]


ml_model = load_model()


# ---------------------------------------------------------------- parsing

def parse_timestamp(value):
    """Turn whatever the agent sent into a timezone-aware UTC datetime."""
    now = datetime.now(timezone.utc)
    if not value:
        return now                                   # no timestamp sent: use arrival time
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return now
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)         # assume UTC if no zone was given
    ts = ts.astimezone(timezone.utc)
    # A clock that is wrong (or a forged timestamp far in the future) would push
    # every detector window forward and make it forget real events. Clamp it.
    if ts > now + MAX_FUTURE_SKEW:
        return now
    return ts


def clean_row(raw):
    """Keep only known columns, fix the timestamp, reject rows missing the basics."""
    row = {key: raw.get(key) for key in LOG_FIELDS}
    for required in ("source_ip", "event_type", "severity", "raw_message"):
        if row[required] is None:
            raise ValueError(f"missing field: {required}")
    row["tenant_id"] = row["tenant_id"] or "default"
    row["timestamp"] = parse_timestamp(raw.get("timestamp"))
    return row


# -------------------------------------------------------------- detectors

def explain_ml_anomaly(feat, row):
    """Plain-English reasons the ML model found this event unusual."""
    factors = []
    rate = int(feat["ip_rate_60s"])
    hour = int(feat["hour"])
    if rate >= 5:
        factors.append(f"{rate} events from this IP in the last 60s")
    if hour < 6 or hour >= 22:
        factors.append(f"activity at an off-hours time ({hour:02d}:00 UTC)")
    if feat["severity_encoded"] >= 2:
        factors.append(f"{row['severity']} severity")
    if feat["event_type_encoded"] == -1:
        factors.append(f"event type '{row['event_type']}' never seen in training data")
    elif feat["event_type_encoded"] in (2, 3):
        factors.append(f"rare event type '{row['event_type']}'")
    if not factors:
        factors.append("unusual combination of hour, event type, severity and IP activity")
    return "Unusual pattern: " + "; ".join(factors)


def ml_alerts(rows):
    """Score every row with the Isolation Forest; return alert dicts for the odd ones."""
    df = pd.DataFrame([{
        "timestamp": r["timestamp"],
        "event_type": r["event_type"],
        "severity": r["severity"],
        "ip_rate_60s": r["_rate"],        # same counter training used (see ml_features.py)
    } for r in rows])
    features = build_features(df)
    predictions = ml_model.predict(features)            # -1 = anomaly, 1 = normal
    scores = ml_model.decision_function(features)       # lower = more anomalous

    found = []
    for i, pred in enumerate(predictions):
        if pred == -1:
            found.append({
                "log_id": rows[i]["id"],
                "source_ip": rows[i]["source_ip"],
                "reason": explain_ml_anomaly(features.iloc[i], rows[i]),
                "score": int(scores[i] * -100),
                # "low" until the evaluation harness (Phase 3) proves how precise ML is.
                "severity": "low",
                "source": "ml",
                "details": {"features": {c: float(features.iloc[i][c]) for c in FEATURE_COLUMNS}},
            })
    return found


def process_rows(db, rows):
    """Save logs, run all detectors, save alerts, commit once."""
    rows.sort(key=lambda r: r["timestamp"])      # detectors assume time order
    db.bulk_insert_mappings(Log, rows, return_defaults=True)   # fills row["id"] for each log

    alerts = []
    for row in rows:
        # 1) sliding window: "too many events from one IP"
        result = detector.check_event(row["source_ip"], event_time=row["timestamp"])
        row["_rate"] = result["count"]
        if result["is_anomaly"]:
            alerts.append({
                "log_id": row["id"],
                "source_ip": row["source_ip"],
                "reason": (f"Burst: {result['count']} '{row['event_type']}' events from "
                           f"{row['source_ip']} within {detector.window_seconds}s "
                           f"(limit {result['threshold']})"),
                "score": result["count"],
                "severity": "medium",
                "source": "sliding_window",
                "details": {"events_in_window": result["count"],
                            "window_seconds": detector.window_seconds,
                            "threshold": result["threshold"]},
            })

        # 2) rules: compromise / spray / distributed
        event = Event(ts=row["timestamp"], source_ip=row["source_ip"],
                      event_type=row["event_type"], outcome=row["outcome"],
                      username=row["username"], host=row["host"], log_id=row["id"])
        for alert in rule_engine.process(event):
            alerts.append({
                "log_id": alert.log_id,
                "source_ip": alert.source_ip,
                "reason": alert.reason,
                "score": alert.score,
                "severity": alert.severity,
                "source": f"rule:{alert.rule}",
                "details": alert.details,
            })

    # 3) machine learning
    if ml_model is not None:
        alerts.extend(ml_alerts(rows))

    if alerts:
        db.bulk_insert_mappings(Anomaly, alerts)
    db.commit()                                   # logs + alerts saved together
    print(f"Saved {len(rows)} logs, {len(alerts)} alerts")


# ------------------------------------------------------------ queue loop

def acknowledge(entry_ids):
    """Tell Redis these are done (ACK) and free the memory (DEL)."""
    if entry_ids:
        redis_client.xack(q.STREAM, q.GROUP, *entry_ids)
        redis_client.xdel(q.STREAM, *entry_ids)


def handle_entries(entries):
    rows, done_ids = [], []
    for entry_id, fields in entries:
        try:
            rows.append(clean_row(json.loads(fields["data"])))
        except Exception as exc:                  # unreadable log: keep it in the dead stream
            redis_client.xadd(q.DEAD_STREAM, {"data": fields.get("data", ""), "error": str(exc)})
            print(f"Dead-lettered an unreadable log: {exc}")
        done_ids.append(entry_id)

    if rows:
        db = SessionLocal()
        try:
            process_rows(db, rows)
        except Exception:
            db.rollback()
            raise                                  # NOT acknowledged -> will be retried
        finally:
            db.close()
    acknowledge(done_ids)


def consume(pending, block_ms=BLOCK_MS):
    """
    Read one batch and process it. pending=True re-reads logs this worker already
    received but never acknowledged (crash recovery); pending=False reads new ones.
    Returns how many logs were handled.
    """
    response = redis_client.xreadgroup(
        q.GROUP, CONSUMER,
        {q.STREAM: "0" if pending else ">"},
        count=BATCH_SIZE,
        block=None if pending else block_ms,
    )
    entries = response[0][1] if response else []
    if entries:
        handle_entries(entries)
    return len(entries)


def dead_letter_stuck_batch(reason):
    """A batch kept failing: park it in the dead stream so the queue can move on."""
    response = redis_client.xreadgroup(q.GROUP, CONSUMER, {q.STREAM: "0"}, count=BATCH_SIZE)
    entries = response[0][1] if response else []
    for _, fields in entries:
        redis_client.xadd(q.DEAD_STREAM, {"data": fields.get("data", ""), "error": reason})
    acknowledge([entry_id for entry_id, _ in entries])
    print(f"Moved {len(entries)} stuck logs to {q.DEAD_STREAM}: {reason}")


def run():
    q.ensure_group(redis_client)
    moved = q.migrate_legacy_list(redis_client)
    if moved:
        print(f"Moved {moved} logs from the old list queue into the stream.")
    print(f"Worker '{CONSUMER}' started. Waiting for logs...")

    pending = True        # on startup, first finish anything left unacknowledged
    failures = 0
    while True:
        try:
            handled = consume(pending)
            failures = 0
            if pending and handled == 0:
                pending = False
        except Exception as exc:                   # keep the worker alive on temporary DB/Redis trouble
            failures += 1
            print(f"Worker error ({failures}/{MAX_RETRIES}): {exc}")
            pending = True                         # retry the same logs next loop
            if failures >= MAX_RETRIES:
                try:
                    dead_letter_stuck_batch(str(exc))
                except Exception as inner:
                    print(f"Could not dead-letter the batch: {inner}")
                failures = 0
            time.sleep(min(2 * failures, 10) or 1)


if __name__ == "__main__":
    run()
