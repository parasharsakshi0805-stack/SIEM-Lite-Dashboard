"""
ml_features.py -- turns a log into the numbers the Isolation Forest looks at.

THE BUG THIS FILE FIXES ("training/serving skew")
-------------------------------------------------
Old feature "ip_event_count":
  * in TRAINING  = how many logs this IP had in the WHOLE database (could be thousands)
  * in the WORKER = how many logs this IP had in the current batch of <= 50
Same name, different meaning. The model learned one scale and was tested on
another, so its scores were unreliable.

THE FIX
-------
One definition, used in both places:
    ip_rate_60s = how many events this IP produced in the 60 seconds up to
                  (and including) this event.
We do not write that counting logic twice. We reuse SlidingWindowDetector for it:
  * training: replay the stored logs through it, in time order (add_ip_rate)
  * serving : the worker reads the same counter live
Same code on both sides means the two cannot drift apart.
"""
import pandas as pd

from detector import SlidingWindowDetector

WINDOW_SECONDS = 60

EVENT_TYPE_MAP = {
    "login_attempt": 0,
    "file_access": 1,
    "port_scan": 2,
    "malware_alert": 3,
    "config_change": 4,
}

SEVERITY_MAP = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

# The exact columns, in the exact order, the model is trained on. It is saved
# inside the model file, and the worker refuses to use a model whose list differs.
FEATURE_COLUMNS = ["hour", "event_type_encoded", "severity_encoded", "ip_rate_60s"]


def add_ip_rate(df, window_seconds=WINDOW_SECONDS):
    """
    TRAINING side: add an `ip_rate_60s` column by replaying logs in time order
    through the same detector the worker uses. Needs columns: timestamp, source_ip.
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp")
    # threshold is huge on purpose: we only want the COUNT, never an alert.
    counter = SlidingWindowDetector(window_seconds=window_seconds, threshold=10**9)
    rates = [
        counter.check_event(ip, event_time=ts.to_pydatetime())["count"]
        for ts, ip in zip(df["timestamp"], df["source_ip"])
    ]
    df["ip_rate_60s"] = rates
    return df


def build_features(df):
    """
    Turn rows into model input. Needs columns:
    timestamp, event_type, severity, ip_rate_60s.
    """
    out = pd.DataFrame(index=df.index)
    out["hour"] = pd.to_datetime(df["timestamp"], utc=True).dt.hour
    out["event_type_encoded"] = df["event_type"].map(EVENT_TYPE_MAP).fillna(-1)
    out["severity_encoded"] = df["severity"].map(SEVERITY_MAP).fillna(-1)
    out["ip_rate_60s"] = df["ip_rate_60s"]
    return out[FEATURE_COLUMNS]
