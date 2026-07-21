import random
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000/logs/ingest/batch"

EVENT_TYPES = ["login_attempt", "file_access", "port_scan", "malware_alert", "config_change"]
SEVERITIES = ["low", "medium", "high", "critical"]

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def generate_logs(n=100):
    logs = []
    for _ in range(n):
        logs.append({
            "source_ip": random_ip(),
            "event_type": random.choice(EVENT_TYPES),
            "severity": random.choice(SEVERITIES),
            "raw_message": f"Simulated event at {datetime.now().isoformat()}",
            "tenant_id": "default"
        })
    return logs

if __name__ == "__main__":
    batch = generate_logs(500)
    response = requests.post(API_URL, json=batch)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")