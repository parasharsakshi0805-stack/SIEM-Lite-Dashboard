from datetime import datetime, timedelta
from detector import SlidingWindowDetector

def test_normal_traffic():
    d = SlidingWindowDetector(window_seconds=60, threshold=10)
    now = datetime.utcnow()
    for i in range(5):
        result = d.check_event('1.2.3.4', now + timedelta(seconds=i))
    assert result['is_anomaly'] == False
    print('PASS: normal traffic not flagged')

def test_spike_traffic():
    d = SlidingWindowDetector(window_seconds=60, threshold=10)
    now = datetime.utcnow()
    anomaly_count = 0
    for i in range(15):
        result = d.check_event('5.6.7.8', now + timedelta(seconds=i))
        if result['is_anomaly']:
            anomaly_count += 1
    assert anomaly_count == 1
    print('PASS: spike traffic flagged exactly once')

def test_window_eviction():
    d = SlidingWindowDetector(window_seconds=10, threshold=5)
    now = datetime.utcnow()
    for i in range(6):
        d.check_event('9.9.9.9', now + timedelta(seconds=i))
    later = now + timedelta(seconds=25)
    result = d.check_event('9.9.9.9', later)
    assert result['count'] == 1
    print('PASS: old events correctly evicted from window')

if __name__ == '__main__':
    test_normal_traffic()
    test_spike_traffic()
    test_window_eviction()
    print('All tests passed.')
