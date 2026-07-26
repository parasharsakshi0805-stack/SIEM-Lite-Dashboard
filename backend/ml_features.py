import pandas as pd

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

def extract_features(logs_df):
    df = logs_df.copy()
    df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
    df["event_type_encoded"] = df["event_type"].map(EVENT_TYPE_MAP).fillna(-1)
    df["severity_encoded"] = df["severity"].map(SEVERITY_MAP).fillna(-1)

    ip_counts = df.groupby("source_ip")["id"].transform("count")
    df["ip_event_count"] = ip_counts

    features = df[["hour", "event_type_encoded", "severity_encoded", "ip_event_count"]]
    return features
