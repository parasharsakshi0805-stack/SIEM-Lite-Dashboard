import requests
import random

API_URL = "http://127.0.0.1:8000/logs/ingest/batch"

def generate_spike(ip="66.66.66.66", n=30):
    logs = []
    for _ in range(n):
        logs.append({
            "source_ip": ip,
            "event_type": "port_scan",
            "severity": "high",
            "raw_message": "Simulated spike traffic",
            "tenant_id": "default"
        })
    return logs

if __name__ == "__main__":
    batch = generate_spike()
    response = requests.post(API_URL, json=batch)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
