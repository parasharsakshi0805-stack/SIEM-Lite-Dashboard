from datetime import datetime, timedelta, timezone

import pandas as pd

from detector import SlidingWindowDetector
from ml_features import FEATURE_COLUMNS, add_ip_rate, build_features


def sample_events():
    t0 = datetime(2026, 10, 2, 3, 0, 0, tzinfo=timezone.utc)
    rows = []
    for i in range(30):
        rows.append({"timestamp": t0 + timedelta(seconds=i * 4),
                     "source_ip": "1.1.1.1" if i % 3 else "2.2.2.2",
                     "event_type": "login_attempt", "severity": "low"})
    return rows


def test_training_and_serving_compute_the_same_rate():
    """The skew bug: both sides must give identical numbers for identical events."""
    rows = sample_events()

    # TRAINING side
    trained = add_ip_rate(pd.DataFrame(rows))

    # SERVING side: exactly what worker.py does, event by event
    live = SlidingWindowDetector(window_seconds=60, threshold=10)
    served = [live.check_event(r["source_ip"], event_time=r["timestamp"])["count"] for r in rows]

    assert list(trained["ip_rate_60s"]) == served


def test_feature_columns_and_encoding():
    df = add_ip_rate(pd.DataFrame(sample_events()))
    features = build_features(df)
    assert list(features.columns) == FEATURE_COLUMNS
    assert (features["hour"] == 3).all()                    # all sample events are at 03:xx UTC
    assert (features["event_type_encoded"] == 0).all()      # login_attempt
