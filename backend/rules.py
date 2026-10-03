"""
rules.py -- detectors that understand WHO did WHAT, not just "how many events".

Why this file exists
--------------------
The old sliding-window detector only counts events per IP. It cannot tell
"50 failed logins" from "50 normal logins", and it can never say the scariest
sentence in security: "...and then they got in".

These detectors are PURE Python: they hold their own state in memory and use the
event's own timestamp as "now" (never the wall clock). Two benefits:
  1. replaying old logs gives the same answer as live processing, and
  2. in Phase 3 the evaluation harness can replay labelled attacks through
     them at full speed to measure precision / recall.

Two detector classes, three kinds of alert:
  * CompromiseDetector -- N failed logins from an IP, then a success from that IP.
  * SprayDetector      -- (a) one IP tries many usernames, (b) many IPs hit one username.
"""
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class Event:
    """One log line, reduced to the fields the rules need."""
    ts: datetime                      # when it HAPPENED (timezone-aware, UTC)
    source_ip: str
    event_type: str
    outcome: Optional[str] = None     # "success" / "failure" / None
    username: Optional[str] = None
    host: Optional[str] = None
    log_id: Optional[int] = None      # DB id of this log, so the alert can point at it


@dataclass
class Alert:
    """What a detector returns. The worker turns it into an Anomaly row."""
    rule: str                         # "compromise" / "spray" / "distributed"
    severity: str                     # "medium" / "high" / "critical"
    source_ip: str
    reason: str                       # the one-sentence story
    score: int                        # rough 0-100 priority (higher = look first)
    details: dict = field(default_factory=dict)   # the evidence, for the UI
    log_id: Optional[int] = None


# ---------------------------------------------------------------- helpers

class _Window:
    """
    Remembers the last `seconds` of (timestamp, value) pairs for ONE key
    (for example: all usernames that one IP failed against).

    `counts` is kept up to date as items enter/leave, so "how many DIFFERENT
    values are in the window?" is len(counts) -- instant, instead of re-scanning
    the whole window on every event.
    """

    def __init__(self, seconds):
        self.seconds = seconds
        self.items = deque()          # oldest on the left
        self.counts = Counter()       # value -> occurrences inside the window
        self.latest = None            # newest timestamp seen (the window's "now")

    def add(self, ts, value):
        # Logs can arrive late or out of order (an agent was offline, then caught
        # up). The window logic needs `items` sorted by time, so:
        if self.latest is not None and ts < self.latest - timedelta(seconds=self.seconds):
            return                                    # too old to matter: already outside the window
        if self.items and ts < self.items[-1][0]:     # slightly late: slot it into the right place
            merged = sorted([*self.items, (ts, value)], key=lambda pair: pair[0])
            self.items = deque(merged)
        else:                                         # normal case: newest goes on the right
            self.items.append((ts, value))
        self.counts[value] += 1
        self.evict(ts)

    def evict(self, now=None):
        """Forget everything older than `seconds` before the newest time we know."""
        if now is not None and (self.latest is None or now > self.latest):
            self.latest = now
        if self.latest is None:
            return
        cutoff = self.latest - timedelta(seconds=self.seconds)
        while self.items and self.items[0][0] < cutoff:
            _, value = self.items.popleft()
            self.counts[value] -= 1
            if self.counts[value] <= 0:
                del self.counts[value]

    def __len__(self):
        return len(self.items)

    def first_time(self):
        return self.items[0][0] if self.items else None


class _Cooldown:
    """Stops the same alert firing again and again (alert fatigue is how SIEMs die)."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.last = {}

    def ready(self, key, now):
        """True (and starts the cooldown) if this key has not alerted recently."""
        previous = self.last.get(key)
        if previous is not None and (now - previous).total_seconds() < self.seconds:
            return False
        self.last[key] = now
        return True

    def prune(self, now):
        for key in [k for k, t in self.last.items() if (now - t).total_seconds() >= self.seconds]:
            del self.last[key]


def _prune_windows(windows, now):
    """Delete windows that are empty, so memory does not grow forever."""
    for key in list(windows):
        windows[key].evict(now)
        if not windows[key].items:
            del windows[key]


def _fmt_duration(seconds):
    seconds = max(1, int(seconds))      # "1s", never "0s"
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    return f"{minutes}m {secs:02d}s" if secs else f"{minutes}m"


def _fmt_time(ts):
    return ts.strftime("%H:%M:%S") + " UTC"


def _names(counter, limit=3):
    """'root, admin, ubuntu +3 more' from a Counter of usernames."""
    named = [(n, c) for n, c in counter.most_common() if n]
    shown = ", ".join(n for n, _ in named[:limit])
    extra = len(named) - limit
    return shown + (f" +{extra} more" if extra > 0 else "")


# ------------------------------------------------------------ the detectors

class CompromiseDetector:
    """
    "N failures, then a success, from the same IP"  ==  probably a guessed password.

    This is the highest-signal alert in the whole product, because it means the
    attack WORKED. Everything else (bursts, sprays) is "someone is knocking".
    """

    def __init__(self, failure_threshold=5, window_seconds=300, cooldown_seconds=600):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.failures = {}                         # ip -> _Window of usernames that failed
        self.cooldown = _Cooldown(cooldown_seconds)

    def process(self, ev):
        if ev.event_type != "login_attempt" or ev.outcome is None or not ev.source_ip:
            return []

        if ev.outcome == "failure":
            window = self.failures.setdefault(ev.source_ip, _Window(self.window_seconds))
            window.add(ev.ts, ev.username)          # remember who they failed as
            return []

        if ev.outcome != "success":
            return []

        window = self.failures.get(ev.source_ip)
        if window is None:
            return []
        window.evict(ev.ts)                          # drop failures older than the window
        failures = len(window)
        if failures < self.failure_threshold:
            return []
        if not self.cooldown.ready((ev.source_ip, ev.username), ev.ts):
            return []

        # ---- build the story --------------------------------------------
        who = ev.username or "an unknown user"
        tried = Counter({n: c for n, c in window.counts.items() if n})
        distinct = len(tried)
        duration = (ev.ts - window.first_time()).total_seconds()
        same_account = window.counts.get(ev.username, 0) if ev.username else 0

        # One user fat-fingering their own password also looks like "failures then
        # success". If every failure was against ONE account and there were only a
        # few, say so honestly and downgrade the severity.
        could_be_typo = distinct <= 1 and failures < 10
        severity = "high" if could_be_typo else "critical"

        if distinct <= 1:
            target = f"all against '{who}'"
        else:
            target = f"{distinct} different usernames: {_names(tried)}"
        reason = (f"Likely compromise: {ev.source_ip} failed to log in {failures} times "
                  f"({target}) over {_fmt_duration(duration)}, then succeeded as '{who}'.")
        if could_be_typo:
            reason += " This could also be the real user mistyping their password."

        host = ev.host or "the host"
        if could_be_typo:
            steps = [f"Confirm with '{who}' that this login was them.",
                     f"If not: check what '{who}' did on {host} after {_fmt_time(ev.ts)}, then reset the password.",
                     f"Consider blocking {ev.source_ip}."]
        else:
            steps = [f"Check what '{who}' did on {host} after {_fmt_time(ev.ts)} "
                     f"(shell history, new processes, new SSH keys).",
                     f"Reset the password for '{who}' and end its active sessions.",
                     f"Block {ev.source_ip}, and confirm '{who}' really logs in from there."]

        return [Alert(
            rule="compromise",
            severity=severity,
            source_ip=ev.source_ip,
            reason=reason,
            score=80 if could_be_typo else 95,
            log_id=ev.log_id,
            details={
                "failures": failures,
                "distinct_usernames": distinct,
                "usernames_tried": [n for n, _ in tried.most_common(5)],
                "success_username": ev.username,
                "failures_on_same_account": same_account,
                "first_failure_at": window.first_time().isoformat(),
                "success_at": ev.ts.isoformat(),
                "duration_seconds": int(duration),
                "window_seconds": self.window_seconds,
                "host": ev.host,
                "next_steps": steps,
            },
        )]

    def prune(self, now):
        _prune_windows(self.failures, now)
        self.cooldown.prune(now)


class SprayDetector:
    """
    Two patterns that a plain per-IP counter cannot see:

      spray       one IP fails against MANY different usernames
                  (each username only a few times, so no volume alarm trips)
      distributed MANY different IPs fail against ONE username
                  (each IP only a few times -- a botnet hiding in the crowd)

    NOTE: on a server exposed to the internet these two are common background
    noise (bots love 'root'), so they are only "medium" severity. The compromise
    rule is the one that should wake someone up.
    """

    def __init__(self, usernames_per_ip=5, ips_per_username=5,
                 window_seconds=300, cooldown_seconds=600):
        self.usernames_per_ip = usernames_per_ip
        self.ips_per_username = ips_per_username
        self.window_seconds = window_seconds
        self.by_ip = {}                    # ip -> _Window of usernames
        self.by_user = {}                  # username -> _Window of ips
        self.cooldown = _Cooldown(cooldown_seconds)

    def process(self, ev):
        if (ev.event_type != "login_attempt" or ev.outcome != "failure"
                or not ev.username or not ev.source_ip):
            return []

        alerts = []
        minutes = max(1, self.window_seconds // 60)

        ip_window = self.by_ip.setdefault(ev.source_ip, _Window(self.window_seconds))
        ip_window.add(ev.ts, ev.username)
        distinct_users = len(ip_window.counts)
        if (distinct_users >= self.usernames_per_ip
                and self.cooldown.ready(("spray", ev.source_ip), ev.ts)):
            alerts.append(Alert(
                rule="spray",
                severity="medium",
                source_ip=ev.source_ip,
                reason=(f"Credential spraying: {ev.source_ip} tried {distinct_users} different "
                        f"usernames ({_names(ip_window.counts)}) within {minutes} minutes."),
                score=60 + min(distinct_users, 40),
                log_id=ev.log_id,
                details={
                    "distinct_usernames": distinct_users,
                    "usernames_tried": [n for n, _ in ip_window.counts.most_common(5)],
                    "total_failures": len(ip_window),
                    "window_seconds": self.window_seconds,
                    "host": ev.host,
                    "next_steps": [
                        f"Block {ev.source_ip}.",
                        "Check that none of the tried usernames exist with weak passwords.",
                    ],
                },
            ))

        user_window = self.by_user.setdefault(ev.username, _Window(self.window_seconds))
        user_window.add(ev.ts, ev.source_ip)
        distinct_ips = len(user_window.counts)
        if (distinct_ips >= self.ips_per_username
                and self.cooldown.ready(("distributed", ev.username), ev.ts)):
            alerts.append(Alert(
                rule="distributed",
                severity="medium",
                source_ip=ev.source_ip,       # the IP that tipped it over; the full list is in details
                reason=(f"Distributed attack on account '{ev.username}': {distinct_ips} different "
                        f"IPs failed to log in as '{ev.username}' within {minutes} minutes."),
                score=60 + min(distinct_ips, 40),
                log_id=ev.log_id,
                details={
                    "username": ev.username,
                    "distinct_ips": distinct_ips,
                    "ips": [ip for ip, _ in user_window.counts.most_common(5)],
                    "total_failures": len(user_window),
                    "window_seconds": self.window_seconds,
                    "host": ev.host,
                    "next_steps": [
                        f"Require key-only login or MFA for '{ev.username}'.",
                        "Check whether ANY of these IPs later logged in successfully.",
                    ],
                },
            ))
        return alerts

    def prune(self, now):
        _prune_windows(self.by_ip, now)
        _prune_windows(self.by_user, now)
        self.cooldown.prune(now)


class RuleEngine:
    """Runs every detector on every event and tidies memory now and then."""

    PRUNE_EVERY = 5000

    def __init__(self, detectors=None):
        self.detectors = detectors if detectors is not None else [CompromiseDetector(), SprayDetector()]
        self._seen = 0

    def process(self, ev):
        alerts = []
        for detector in self.detectors:
            alerts.extend(detector.process(ev))
        self._seen += 1
        if self._seen % self.PRUNE_EVERY == 0:
            for detector in self.detectors:
                detector.prune(ev.ts)
        return alerts
