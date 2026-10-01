import requests

from seed_data import login_session, API_URL


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
    session = login_session()
    batch = generate_spike()
    response = session.post(API_URL, json=batch)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print("Within a few seconds the sliding-window detector should flag 66.66.66.66 on the Anomalies page.")