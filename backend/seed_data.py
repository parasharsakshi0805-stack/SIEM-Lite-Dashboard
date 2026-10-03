import getpass
import random
import sys
import requests
from datetime import datetime, timedelta, timezone

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
# Realistic mix: most traffic is boring logins and file access; scans/malware are rare.
EVENT_WEIGHTS = [55, 25, 8, 2, 10]
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [60, 25, 12, 3]
USERS = ["alice", "bob", "deploy", "carol"]
# Probability of an event at each UTC hour 0..23: busy 08:00-17:00, quiet at night.
HOUR_WEIGHTS = [1, 1, 1, 1, 1, 1,   3, 5, 8, 8, 8, 8,   8, 8, 8, 8, 8, 6,   4, 3, 2, 2, 1, 1]


def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


# A small set of "regular" visitors (staff, services). Real traffic has repeat
# visitors; a fresh random IP for every event does not.
REGULAR_IPS = [random_ip() for _ in range(40)]


def random_timestamp(days_back=7):
    """A believable moment in the past week (so the ML 'hour' feature has real variety)."""
    now = datetime.now(timezone.utc)
    hour = random.choices(range(24), weights=HOUR_WEIGHTS)[0]
    day = now - timedelta(days=random.randint(0, days_back - 1))
    ts = day.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    if ts > now:                       # never invent events from the future
        ts -= timedelta(days=1)
    return ts


def generate_logs(n=1000):
    """
    Makes n logs grouped into short "sessions": one visitor does 1-6 things within
    a minute. That gives the ML feature `ip_rate_60s` a normal range of 1-6.
    (If every event had its own IP the rate would always be 1, the model could
    not learn anything about rate, and it would never notice a burst.)
    """
    logs = []
    while len(logs) < n:
        ip = random.choice(REGULAR_IPS) if random.random() < 0.8 else random_ip()
        start = random_timestamp()
        for step in range(random.choices([1, 2, 3, 4, 5, 6], weights=[40, 25, 15, 10, 6, 4])[0]):
            event_type = random.choices(EVENT_TYPES, weights=EVENT_WEIGHTS)[0]
            log = {
                "source_ip": ip,
                "event_type": event_type,
                "severity": random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0],
                "raw_message": f"Simulated {event_type} event",
                "tenant_id": "default",
                "timestamp": (start + timedelta(seconds=step * random.randint(2, 9))).isoformat(),
                "host": "seed-host",
            }
            if event_type == "login_attempt":
                log["username"] = random.choice(USERS)
                log["outcome"] = random.choices(["success", "failure"], weights=[90, 10])[0]
            logs.append(log)
    return logs[:n]


if __name__ == "__main__":
    session = login_session()
    batch = generate_logs(1000)           # 1000 is the API's per-request maximum
    response = session.post(API_URL, json=batch)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
