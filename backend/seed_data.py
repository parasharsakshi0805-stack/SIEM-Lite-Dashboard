import getpass
import random
import sys
import requests
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000"
API_URL = f"{BASE_URL}/logs/ingest/batch"


def login_session():
    """Log in and return a requests.Session that keeps the login cookie."""
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    session = requests.Session()
    resp = session.post(f"{BASE_URL}/auth/login", data={"username": username, "password": password})
    if resp.status_code == 401:
        print("Login failed: wrong username or password.")
        sys.exit(1)
    if resp.status_code == 429:
        print("Too many login attempts. Wait one minute and try again.")
        sys.exit(1)
    resp.raise_for_status()
    return session


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
    session = login_session()
    batch = generate_logs(500)
    response = session.post(API_URL, json=batch)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")