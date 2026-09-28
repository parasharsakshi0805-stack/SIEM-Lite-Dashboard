#!/usr/bin/env python3
import argparse
import random
import time
from datetime import datetime

USERNAMES = ["deploy", "admin", "ubuntu", "root", "test", "backup", "git"]
FAKE_USER_POOL = ["alice", "bob", "deploy"]


def fake_ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def log_line(host: str, message: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"{ts} {host} sshd[{random.randint(1000,9999)}]: {message}\n"


def normal_event(rng: random.Random) -> str:
    user = rng.choice(FAKE_USER_POOL)
    ip = fake_ip(rng)
    port = rng.randint(1024, 65000)
    return log_line("demo-host", f"Accepted password for {user} from {ip} port {port} ssh2")


def attack_burst(rng: random.Random, out_path: str, count: int = 15):
    attacker_ip = fake_ip(rng)
    with open(out_path, "a") as f:
        for _ in range(count):
            user = rng.choice(USERNAMES)
            port = rng.randint(1024, 65000)
            f.write(log_line("demo-host", f"Failed password for invalid user {user} from {attacker_ip} port {port} ssh2"))
            f.flush()
            time.sleep(0.3)
    print(f"Wrote {count} failed-login lines from a single fake IP ({attacker_ip}) to {out_path}")

def baseline_burst(rng: random.Random, out_path: str, count: int):
    print(f"Writing {count} normal-looking lines to {out_path} ...")
    with open(out_path, "a") as f:
        for i in range(count):
            f.write(normal_event(rng))
            f.flush()
            time.sleep(0.05)
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
    parser.add_argument("--mode", choices=["quiet", "attack","baseline"], default="quiet")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--count", type=int, default=600)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    open(args.out, "a").close()

    if args.mode == "attack":
        attack_burst(rng, args.out)
    elif args.mode == "baseline":
        baseline_burst(rng, args.out, args.count)
    else:
        try:
            quiet_stream(rng, args.out)
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()