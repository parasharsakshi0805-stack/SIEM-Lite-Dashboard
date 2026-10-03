from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from database import engine
from ml_features import FEATURE_COLUMNS, add_ip_rate, build_features

MODEL_PATH = "isolation_forest_model.joblib"


def load_logs():
    query = "SELECT id, timestamp, source_ip, event_type, severity FROM logs"
    return pd.read_sql(query, engine)


def train():
    df = load_logs()
    if len(df) < 50:
        print(f"Not enough data to train ({len(df)} rows). Need at least 50.")
        return

    df = add_ip_rate(df)               # same counting logic the worker uses live
    features = build_features(df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # assume ~5% of data is anomalous
        random_state=42,
    )
    model.fit(features)

    # Save the model WITH a label saying which features it expects. The worker
    # checks the label, so an old/mismatched model can never be used silently.
    bundle = {
        "model": model,
        "features": FEATURE_COLUMNS,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "rows": len(df),
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"Model trained on {len(df)} rows and saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
