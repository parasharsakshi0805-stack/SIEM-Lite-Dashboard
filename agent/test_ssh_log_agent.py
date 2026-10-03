from datetime import datetime, timezone

from ssh_log_agent import parse_line, parse_header

NOW = datetime(2026, 10, 2, 12, 0, 0).astimezone()


def test_failed_password_invalid_user_has_username_host_outcome_timestamp():
    line = "Oct  2 10:15:01 web-1 sshd[991]: Failed password for invalid user admin from 203.0.113.7 port 4422 ssh2"
    ev = parse_line(line, "default", now=NOW)
    assert (ev.source_ip, ev.username, ev.host, ev.outcome) == ("203.0.113.7", "admin", "web-1", "failure")
    assert ev.timestamp is not None and ev.timestamp.endswith("+00:00")     # normalised to UTC


def test_failed_password_valid_user_is_not_confused_with_invalid_user():
    line = "Oct  2 10:15:01 web-1 sshd[991]: Failed password for deploy from 203.0.113.7 port 4422 ssh2"
    assert parse_line(line, "default", now=NOW).username == "deploy"


def test_accepted_login_is_a_success():
    line = "Oct  2 10:15:09 web-1 sshd[995]: Accepted publickey for deploy from 203.0.113.7 port 5000 ssh2"
    ev = parse_line(line, "default", now=NOW)
    assert ev.outcome == "success" and ev.username == "deploy"


def test_companion_lines_are_shipped_but_not_counted_as_failures():
    """One failed attempt writes 3 lines. Only 'Failed password' may count, or 3 attempts look like 9."""
    invalid = parse_line("Oct  2 10:15:00 web-1 sshd[1]: Invalid user bob from 1.2.3.4 port 22", "d", now=NOW)
    pam = parse_line("Oct  2 10:15:00 web-1 sshd[1]: pam_unix(sshd:auth): authentication failure; "
                     "logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=bob", "d", now=NOW)
    assert invalid.outcome is None and invalid.username == "bob"
    assert pam.outcome is None and pam.username == "bob"


def test_iso_timestamp_with_offset_is_converted_to_utc():
    ts, host = parse_header("2026-10-02T10:15:01.123456+05:30 web-1 sshd[1]: x", now=NOW)
    assert host == "web-1"
    assert datetime.fromisoformat(ts) == datetime(2026, 10, 2, 4, 45, 1, 123456, tzinfo=timezone.utc)


def test_december_line_read_in_january_is_not_a_year_in_the_future():
    jan_1 = datetime(2027, 1, 1, 0, 5, 0).astimezone()
    ts, _ = parse_header("Dec 31 23:59:00 web-1 sshd[1]: x", now=jan_1)
    assert datetime.fromisoformat(ts).year == 2026


def test_unrelated_line_is_ignored():
    assert parse_line("Oct  2 10:15:01 web-1 CRON[1]: session opened", "default", now=NOW) is None
