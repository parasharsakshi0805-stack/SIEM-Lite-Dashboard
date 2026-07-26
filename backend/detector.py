from collections import deque
from datetime import datetime, timedelta

WINDOW_SECONDS = 60
THRESHOLD = 10  # more than 10 events per IP within the window = anomaly

class SlidingWindowDetector:
    def __init__(self, window_seconds=WINDOW_SECONDS, threshold=THRESHOLD):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.ip_windows = {}  # source_ip -> deque of timestamps
        self.alerted_ips = set()  # IPs currently in an alerted state

    def _evict_old(self, dq, now):
        cutoff = now - timedelta(seconds=self.window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()

    def check_event(self, source_ip, event_time=None):
        now = event_time or datetime.utcnow()

        if source_ip not in self.ip_windows:
            self.ip_windows[source_ip] = deque()

        dq = self.ip_windows[source_ip]
        self._evict_old(dq, now)
        dq.append(now)

        count = len(dq)
        over_threshold = count > self.threshold

        is_new_anomaly = over_threshold and source_ip not in self.alerted_ips

        if over_threshold:
            self.alerted_ips.add(source_ip)
        else:
            self.alerted_ips.discard(source_ip)

        return {
            "is_anomaly": is_new_anomaly,
            "count": count,
            "threshold": self.threshold,
        }
