from datetime import datetime, timedelta, timezone

from rules import CompromiseDetector, SprayDetector, RuleEngine, Event

T0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)


def login(sec, ip, user, outcome, log_id=None):
    return Event(ts=T0 + timedelta(seconds=sec), source_ip=ip, event_type="login_attempt",
                 outcome=outcome, username=user, host="web-1", log_id=log_id)


def feed(detector, events):
    alerts = []
    for ev in events:
        alerts.extend(detector.process(ev))
    return alerts


# ---------------------------------------------------------- compromise

def test_failures_then_success_is_critical_compromise():
    d = CompromiseDetector()
    users = ["root", "admin", "ubuntu", "root", "test", "admin", "root"]
    events = [login(i * 10, "9.9.9.9", u, "failure") for i, u in enumerate(users)]
    events.append(login(80, "9.9.9.9", "deploy", "success", log_id=42))
    alerts = feed(d, events)

    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == "compromise" and a.severity == "critical"
    assert a.log_id == 42                                  # points at the successful login
    assert a.details["failures"] == 7
    assert a.details["distinct_usernames"] == 4
    assert a.details["success_username"] == "deploy"
    assert "succeeded as 'deploy'" in a.reason
    assert len(a.details["next_steps"]) == 3


def test_below_threshold_does_not_alert():
    d = CompromiseDetector(failure_threshold=5)
    events = [login(i, "9.9.9.9", "root", "failure") for i in range(4)]
    events.append(login(10, "9.9.9.9", "root", "success"))
    assert feed(d, events) == []


def test_old_failures_outside_window_do_not_count():
    d = CompromiseDetector(failure_threshold=5, window_seconds=300)
    events = [login(i, "9.9.9.9", "root", "failure") for i in range(6)]
    events.append(login(1000, "9.9.9.9", "root", "success"))   # 16 minutes later
    assert feed(d, events) == []


def test_success_from_a_different_ip_does_not_alert():
    d = CompromiseDetector()
    events = [login(i, "9.9.9.9", "root", "failure") for i in range(8)]
    events.append(login(20, "1.1.1.1", "root", "success"))
    assert feed(d, events) == []


def test_same_account_few_failures_is_high_and_mentions_typo():
    d = CompromiseDetector()
    events = [login(i * 5, "5.5.5.5", "alice", "failure") for i in range(5)]
    events.append(login(40, "5.5.5.5", "alice", "success"))
    alerts = feed(d, events)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert "mistyping" in alerts[0].reason


def test_cooldown_stops_duplicate_alerts():
    d = CompromiseDetector(cooldown_seconds=600)
    events = [login(i, "9.9.9.9", u, "failure") for i, u in enumerate(["a", "b", "c", "d", "e", "f"])]
    events += [login(10, "9.9.9.9", "deploy", "success"), login(20, "9.9.9.9", "deploy", "success")]
    assert len(feed(d, events)) == 1


def test_non_login_events_are_ignored():
    d = CompromiseDetector()
    ev = Event(ts=T0, source_ip="1.1.1.1", event_type="file_access", outcome="success")
    assert d.process(ev) == []


# -------------------------------------------------------------- spray

def test_one_ip_many_usernames_is_spray():
    d = SprayDetector(usernames_per_ip=5)
    names = ["root", "admin", "ubuntu", "test", "git", "oracle"]
    alerts = feed(d, [login(i * 5, "7.7.7.7", n, "failure") for i, n in enumerate(names)])
    spray = [a for a in alerts if a.rule == "spray"]
    assert len(spray) == 1                                   # once, thanks to the cooldown
    assert spray[0].details["distinct_usernames"] == 5


def test_many_ips_one_username_is_distributed():
    d = SprayDetector(ips_per_username=5)
    alerts = feed(d, [login(i * 5, f"10.0.0.{i}", "root", "failure") for i in range(6)])
    dist = [a for a in alerts if a.rule == "distributed"]
    assert len(dist) == 1
    assert dist[0].details["username"] == "root"
    assert dist[0].details["distinct_ips"] == 5


def test_repeating_one_username_from_one_ip_is_not_spray():
    d = SprayDetector()
    assert feed(d, [login(i, "7.7.7.7", "root", "failure") for i in range(30)]) == []


# -------------------------------------------------------------- engine

def test_engine_runs_all_detectors_and_prune_is_safe():
    engine = RuleEngine()
    engine.PRUNE_EVERY = 3                                   # force pruning during the test
    alerts = []
    for i, u in enumerate(["root", "admin", "ubuntu", "test", "git", "oracle"]):
        alerts += engine.process(login(i, "9.9.9.9", u, "failure"))
    alerts += engine.process(login(30, "9.9.9.9", "deploy", "success"))
    assert {a.rule for a in alerts} == {"spray", "compromise"}


# ------------------------------------------------- late / out-of-order logs

def test_out_of_order_logs_do_not_inflate_counts():
    """An agent that was offline and catches up sends OLD events AFTER newer ones."""
    d = SprayDetector(ips_per_username=5)
    # five IPs, but each event is hours apart and arrives scrambled -> must NOT alert
    scrambled = [7200, 100, 14400, 50, 21600, 3600, 10800]
    alerts = feed(d, [login(sec, f"10.0.0.{i}", "root", "failure") for i, sec in enumerate(scrambled)])
    assert alerts == []


def test_slightly_late_event_still_counts():
    d = CompromiseDetector(failure_threshold=5)
    events = [login(10, "9.9.9.9", "a", "failure"), login(20, "9.9.9.9", "b", "failure"),
              login(40, "9.9.9.9", "c", "failure"), login(50, "9.9.9.9", "d", "failure"),
              login(30, "9.9.9.9", "e", "failure"),            # arrived late, still inside the window
              login(60, "9.9.9.9", "deploy", "success")]
    assert len(feed(d, events)) == 1
