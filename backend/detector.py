from collections import deque
from datetime import datetime, timedelta

WINDOW_SECONDS = 60
THRESHOLD = 10  # more than 10 events per IP within the window = anomaly

class SlidingWindowDetector:
    def __init__(self, window_seconds=WINDOW_SECONDS, threshold=THRESHOLD):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.ip_windows = {}  # source_ip -> deque of timestamps (kept sorted, oldest first)
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

        # NEW: logs can arrive late or out of order (an agent was offline and is
        # catching up). The old code just appended them, so a log from days ago
        # sat in the window next to a log from now and the count came out too big.
        # "newest" = the latest time we have seen for this IP; the window is
        # measured back from THAT, not from whichever log happened to arrive last.
        newest = max(now, dq[-1]) if dq else now

        if now < newest - timedelta(seconds=self.window_seconds):
            # Too old to belong to the current window: it cannot cause or join a
            # burst. Count it as a lone event and leave all state untouched.
            return {"is_anomaly": False, "count": 1, "threshold": self.threshold}

        if dq and now < dq[-1]:
            # Slightly late: put it in its correct place so the deque stays sorted.
            dq = deque(sorted([*dq, now]))
            self.ip_windows[source_ip] = dq
        else:
            dq.append(now)                      # normal case: newest on the right
        self._evict_old(dq, newest)

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
