import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from database import engine
from ml_features import extract_features

def load_logs():
    query = "SELECT id, timestamp, source_ip, event_type, severity FROM logs"
    df = pd.read_sql(query, engine)
    return df

def train():
    df = load_logs()
    if len(df) < 50:
        print(f"Not enough data to train ({len(df)} rows). Need at least 50.")
        return

    features = extract_features(df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # assume ~5% of data is anomalous
        random_state=42,
    )
    model.fit(features)

    joblib.dump(model, "isolation_forest_model.joblib")
    print(f"Model trained on {len(df)} rows and saved to isolation_forest_model.joblib")

if __name__ == "__main__":
    train()
