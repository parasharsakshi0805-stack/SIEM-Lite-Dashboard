"""
End-to-end: API-side enqueue -> Redis stream -> worker -> database -> alerts.
Uses fakeredis (in-memory Redis) and SQLite (in-memory DB), so it needs no servers.
"""
from datetime import datetime, timedelta, timezone

import fakeredis
import pytest

import log_queue as q
import worker
from database import SessionLocal, engine, Base
from models import Anomaly, Log
from rules import RuleEngine
from detector import SlidingWindowDetector
from schemas import LogCreate


@pytest.fixture(autouse=True)
def fresh_world(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(worker, "redis_client", fake)
    monkeypatch.setattr(worker, "ml_model", None)                       # ML tested separately
    monkeypatch.setattr(worker, "rule_engine", RuleEngine())            # clean detector memory
    monkeypatch.setattr(worker, "detector", SlidingWindowDetector(60, 10))
    q.ensure_group(fake)
    return fake


def make_log(sec, ip, user, outcome, base):
    return LogCreate(source_ip=ip, event_type="login_attempt",
                     severity="medium" if outcome == "failure" else "low",
                     raw_message=f"{outcome} for {user}", username=user, host="web-1",
                     outcome=outcome, timestamp=base + timedelta(seconds=sec))


def test_compromise_flows_through_the_whole_pipeline(fresh_world):
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    logs = [make_log(i * 5, "9.9.9.9", u, "failure", base)
            for i, u in enumerate(["root", "admin", "ubuntu", "test", "root", "admin"])]
    logs.append(make_log(40, "9.9.9.9", "deploy", "success", base))
    q.enqueue(fresh_world, logs)

    assert worker.consume(pending=False, block_ms=10) == 7

    db = SessionLocal()
    try:
        assert db.query(Log).count() == 7
        stored = db.query(Log).order_by(Log.id).first()
        # the agent's event time was kept (not replaced by "now")
        assert abs((stored.timestamp.replace(tzinfo=timezone.utc) - base).total_seconds()) < 1
        assert stored.username == "root" and stored.host == "web-1" and stored.outcome == "failure"

        alert = db.query(Anomaly).filter(Anomaly.source == "rule:compromise").one()
        assert alert.severity == "critical"
        success_log = db.query(Log).filter(Log.outcome == "success").one()
        assert alert.log_id == success_log.id                            # real log_id now
        assert alert.details["failures"] == 6
    finally:
        db.close()

    # acknowledged AND deleted: nothing left waiting or pending
    assert fresh_world.xlen(q.STREAM) == 0
    assert fresh_world.xpending(q.STREAM, q.GROUP)["pending"] == 0


def test_crash_before_ack_means_logs_are_retried_not_lost(fresh_world, monkeypatch):
    base = datetime.now(timezone.utc) - timedelta(minutes=1)
    q.enqueue(fresh_world, [make_log(0, "1.2.3.4", "alice", "success", base)])

    def boom(db, rows):
        raise RuntimeError("database went away")

    monkeypatch.setattr(worker, "process_rows", boom)
    with pytest.raises(RuntimeError):
        worker.consume(pending=False, block_ms=10)
    assert fresh_world.xpending(q.STREAM, q.GROUP)["pending"] == 1       # still waiting, not lost

    monkeypatch.undo()                                                   # "database is back"
    monkeypatch.setattr(worker, "redis_client", fresh_world)
    monkeypatch.setattr(worker, "ml_model", None)
    assert worker.consume(pending=True) == 1                             # crash-recovery read
    db = SessionLocal()
    try:
        assert db.query(Log).count() == 1
    finally:
        db.close()
    assert fresh_world.xpending(q.STREAM, q.GROUP)["pending"] == 0


def test_unreadable_log_goes_to_dead_stream(fresh_world):
    fresh_world.xadd(q.STREAM, {"data": "this is not json"})
    assert worker.consume(pending=False, block_ms=10) == 1
    assert fresh_world.xlen(q.DEAD_STREAM) == 1
    assert fresh_world.xlen(q.STREAM) == 0


def test_future_timestamp_is_clamped():
    far_future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    assert worker.parse_timestamp(far_future) <= datetime.now(timezone.utc) + timedelta(seconds=5)


def test_naive_and_z_timestamps_become_utc():
    assert worker.parse_timestamp("2026-10-02T10:00:00").tzinfo is not None
    assert worker.parse_timestamp("2026-10-02T10:00:00Z").utcoffset() == timedelta(0)


def test_queue_full_is_refused(fresh_world, monkeypatch):
    monkeypatch.setattr(q, "MAX_QUEUE_LENGTH", 2)
    base = datetime.now(timezone.utc)
    with pytest.raises(q.QueueFull):
        q.enqueue(fresh_world, [make_log(i, "1.1.1.1", "a", "failure", base) for i in range(3)])


def test_legacy_list_is_migrated(fresh_world):
    fresh_world.rpush(q.LEGACY_LIST, '{"source_ip":"1.1.1.1","event_type":"x","severity":"low","raw_message":"old"}')
    assert q.migrate_legacy_list(fresh_world) == 1
    assert fresh_world.xlen(q.STREAM) == 1
