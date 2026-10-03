from datetime import datetime, timedelta, timezone

from detector import SlidingWindowDetector

T0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)


def test_old_logs_arriving_late_do_not_trigger_a_burst():
    d = SlidingWindowDetector(window_seconds=60, threshold=10)
    # 12 events from ONE ip, hours apart, delivered in scrambled order
    offsets = [7200, 100, 14400, 50, 21600, 3600, 10800, 300, 9000, 600, 12000, 1800]
    flagged = [d.check_event("1.2.3.4", T0 + timedelta(seconds=s))["is_anomaly"] for s in offsets]
    assert not any(flagged)


def test_real_burst_still_detected_when_one_event_is_slightly_late():
    d = SlidingWindowDetector(window_seconds=60, threshold=10)
    seconds = list(range(0, 12))
    seconds[5], seconds[6] = seconds[6], seconds[5]          # two swapped
    flagged = [d.check_event("1.2.3.4", T0 + timedelta(seconds=s))["is_anomaly"] for s in seconds]
    assert sum(flagged) == 1
