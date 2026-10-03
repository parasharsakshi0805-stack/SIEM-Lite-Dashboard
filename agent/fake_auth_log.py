#!/usr/bin/env python3
"""
Writes FAKE sshd log lines so you can demo and test the SIEM without a real server.

Modes:
  quiet        slow trickle of normal logins (default; Ctrl+C to stop)
  baseline     lots of normal-looking logins quickly (training data)
  attack       burst of failures from one IP            -> "Burst" alert (sliding window)
  compromise   failures from one IP, THEN a success     -> CRITICAL "Likely compromise" alert
  typo         one user fails 5 times, then succeeds    -> HIGH alert that says "could be a typo"
  spray        one IP tries many usernames              -> "Credential spraying" alert
  distributed  many IPs all try one username            -> "Distributed attack" alert
"""
import argparse
import random
import time
from datetime import datetime

USERNAMES = ["deploy", "admin", "ubuntu", "root", "test", "backup", "git"]
SPRAY_USERNAMES = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "guest", "pi", "ftp"]
FAKE_USER_POOL = ["alice", "bob", "deploy"]
HOST = "demo-host"


def fake_ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def log_line(host: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"{ts} {host} sshd[{random.randint(1000,9999)}]: {message}\n"


def failed_line(user: str, ip: str, rng: random.Random, invalid: bool = True) -> str:
    kind = "invalid user " if invalid else ""
    return log_line(HOST, f"Failed password for {kind}{user} from {ip} port {rng.randint(1024, 65000)} ssh2")


def accepted_line(user: str, ip: str, rng: random.Random) -> str:
    return log_line(HOST, f"Accepted password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2")


def normal_event(rng: random.Random) -> str:
    return accepted_line(rng.choice(FAKE_USER_POOL), fake_ip(rng), rng)


def write_lines(out_path: str, lines, delay: float):
    with open(out_path, "a") as f:
        for line in lines:
            f.write(line)
            f.flush()
            time.sleep(delay)


def attack_burst(rng, out_path, count=15):
    attacker_ip = fake_ip(rng)
    lines = [failed_line(rng.choice(USERNAMES), attacker_ip, rng) for _ in range(count)]
    write_lines(out_path, lines, 0.3)
    print(f"Wrote {count} failed-login lines from a single fake IP ({attacker_ip}) to {out_path}")


def compromise(rng, out_path, failures=8):
    """The scary one: the attacker guesses several usernames, then gets in as 'deploy'."""
    ip = fake_ip(rng)
    lines = [failed_line(rng.choice(["root", "admin", "ubuntu", "test"]), ip, rng) for _ in range(failures)]
    lines.append(accepted_line("deploy", ip, rng))
    write_lines(out_path, lines, 0.2)
    print(f"Wrote {failures} failures then a SUCCESS as 'deploy' from {ip} to {out_path}")


def typo(rng, out_path, failures=5):
    """A real user mistypes their password a few times, then gets it right."""
    ip = fake_ip(rng)
    lines = [failed_line("alice", ip, rng, invalid=False) for _ in range(failures)]
    lines.append(accepted_line("alice", ip, rng))
    write_lines(out_path, lines, 0.2)
    print(f"Wrote {failures} failures then a success as 'alice' from {ip} to {out_path}")


def spray(rng, out_path, usernames=8):
    ip = fake_ip(rng)
    names = rng.sample(SPRAY_USERNAMES, k=min(usernames, len(SPRAY_USERNAMES)))
    write_lines(out_path, [failed_line(n, ip, rng) for n in names], 0.2)
    print(f"Wrote 1 failure each for {len(names)} usernames from {ip} to {out_path}")


def distributed(rng, out_path, ips=7, target="root"):
    lines = [failed_line(target, fake_ip(rng), rng, invalid=False) for _ in range(ips)]
    write_lines(out_path, lines, 0.2)
    print(f"Wrote failures against '{target}' from {ips} different IPs to {out_path}")


def baseline_burst(rng: random.Random, out_path: str, count: int):
    print(f"Writing {count} normal-looking lines to {out_path} ...")
    write_lines(out_path, (normal_event(rng) for _ in range(count)), 0.05)
    print("Done.")


def quiet_stream(rng: random.Random, out_path: str):
    print(f"Trickling normal-looking traffic into {out_path} (Ctrl+C to stop)...")
    with open(out_path, "a") as f:
        while True:
            f.write(normal_event(rng))
            f.flush()
            time.sleep(rng.uniform(2, 6))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="demo_auth.log")
    parser.add_argument("--mode", default="quiet",
                        choices=["quiet", "attack", "baseline", "compromise", "typo", "spray", "distributed"])
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--count", type=int, default=600)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    open(args.out, "a").close()

    if args.mode == "attack":
        attack_burst(rng, args.out)
    elif args.mode == "compromise":
        compromise(rng, args.out)
    elif args.mode == "typo":
        typo(rng, args.out)
    elif args.mode == "spray":
        spray(rng, args.out)
    elif args.mode == "distributed":
        distributed(rng, args.out)
    elif args.mode == "baseline":
        baseline_burst(rng, args.out, args.count)
    else:
        try:
            quiet_stream(rng, args.out)
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
