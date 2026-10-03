"""
log_queue.py -- the "waiting room" between the API and the worker.

BEFORE: a Redis LIST. The worker did LPOP, which REMOVES the log from Redis
immediately. If the worker crashed before saving it to Postgres, the log was gone.

NOW: a Redis STREAM with a consumer group. Reading a log does NOT remove it. It
stays "pending" until the worker says "ACK, saved". If the worker crashes, the
pending logs are still there and get re-processed on restart.

(File is called log_queue.py, not queue.py, because "queue" is a Python built-in
module name and would cause confusing import bugs.)
"""
import json

import redis

STREAM = "log_stream"            # where new logs wait
GROUP = "siem-workers"           # the worker's "consumer group" (Redis tracks progress per group)
DEAD_STREAM = "log_dead"         # logs that could never be processed (so we never lose them silently)
LEGACY_LIST = "log_queue"        # the OLD list; drained once so nothing is stranded after upgrading
MAX_QUEUE_LENGTH = 200_000       # backpressure: refuse new logs if this many are already waiting


class QueueFull(Exception):
    """Raised when the waiting room is full; the API turns it into HTTP 503."""


def enqueue(client, logs):
    """Add a list of LogCreate objects to the stream (one Redis round-trip)."""
    if client.xlen(STREAM) + len(logs) > MAX_QUEUE_LENGTH:
        raise QueueFull()
    pipe = client.pipeline()
    for log in logs:
        # mode="json" turns datetimes into ISO strings so json.dumps works.
        pipe.xadd(STREAM, {"data": json.dumps(log.model_dump(mode="json"))})
    pipe.execute()


def ensure_group(client):
    """Create the consumer group once. id="0" = start from the very first log."""
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):   # "already exists" is fine
            raise


def migrate_legacy_list(client):
    """Move anything left in the old list into the stream. Returns how many moved."""
    moved = 0
    while True:
        item = client.lpop(LEGACY_LIST)
        if item is None:
            return moved
        client.xadd(STREAM, {"data": item})
        moved += 1
