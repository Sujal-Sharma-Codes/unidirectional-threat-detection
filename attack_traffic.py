"""
attack_traffic.py

Simulates two common real-world email login attacks:
1. Brute force - ONE username, MANY passwords tried rapidly, from one IP.
2. Credential spray - MANY usernames, 1-2 common passwords, spread across
   several simulated source IPs (mimics a botnet), to dodge simple
   per-account lockouts.

Both run with little/no delay between attempts, which is the key behavioral
signal our detector will learn (real users don't log in 10x per second).
"""

import socket
import random
import time
import argparse
import string

HOST = "127.0.0.1"
PORT = 9999

TARGET_USERNAME = "priya.sharma"  # brute force target
SPRAY_USERNAMES = [
    "priya.sharma", "rahul.verma", "admin", "test", "support",
    "info", "sales", "webmaster", "root", "office",
]
COMMON_PASSWORDS = ["Password1", "123456", "Welcome1", "Admin@123", "Summer2024"]


def send_attempt(ip, username, password, label, sim_ts=None):
    msg = f"IP:{ip}\nUSER:{username}\nPASS:{password}\nLABEL:{label}\n"
    if sim_ts is not None:
        msg += f"TS:{sim_ts}\n"
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.sendall(msg.encode())
            resp = s.recv(64).decode().strip()
        return resp
    except ConnectionRefusedError:
        print("[attack_traffic] Server not running. Start server.py first.")
        raise


def random_password(length=8):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def run_bruteforce(n_attempts: int, source_ip: str, delay: float, compressed: bool = False):
    print(f"[attack_traffic] BRUTE FORCE: {n_attempts} attempts on '{TARGET_USERNAME}' from {source_ip}"
          f"{' (compressed)' if compressed else ''}")
    sim_clock = time.time() - random.uniform(60, 3600) if compressed else None
    for i in range(n_attempts):
        pwd = random_password()
        # attackers fire rapidly: 10-200ms between tries, no human pacing
        gap = random.uniform(0.01, 0.2)
        resp = send_attempt(source_ip, TARGET_USERNAME, pwd, label="ATTACK_BRUTEFORCE", sim_ts=sim_clock)
        print(f"[attack_traffic][bruteforce] {i+1}/{n_attempts} -> {resp}")
        if compressed:
            sim_clock += gap
        elif delay:
            time.sleep(delay)


def run_spray(n_attempts: int, ip_pool: list, delay: float, compressed: bool = False):
    print(f"[attack_traffic] CREDENTIAL SPRAY: {n_attempts} attempts across {len(ip_pool)} simulated IPs"
          f"{' (compressed)' if compressed else ''}")
    sim_clock = time.time() - random.uniform(60, 3600) if compressed else None
    for i in range(n_attempts):
        ip = random.choice(ip_pool)
        user = random.choice(SPRAY_USERNAMES)
        pwd = random.choice(COMMON_PASSWORDS)
        gap = random.uniform(0.05, 0.5)
        resp = send_attempt(ip, user, pwd, label="ATTACK_SPRAY", sim_ts=sim_clock)
        print(f"[attack_traffic][spray] {i+1}/{n_attempts} ip={ip} user={user} -> {resp}")
        if compressed:
            sim_clock += gap
        elif delay:
            time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["bruteforce", "spray", "both"], default="both")
    parser.add_argument("--attempts", type=int, default=60, help="attempts per attack")
    parser.add_argument("--delay", type=float, default=0.05, help="seconds between attempts (live mode)")
    parser.add_argument("--compressed", action="store_true", help="dataset-generation mode (fast, simulated timestamps)")
    parser.add_argument("--source-ip", type=str, default="203.0.113.77", help="attacker source ip (bruteforce mode)")
    args = parser.parse_args()

    if args.mode in ("bruteforce", "both"):
        run_bruteforce(args.attempts, source_ip=args.source_ip, delay=args.delay, compressed=args.compressed)
    if args.mode in ("spray", "both"):
        spray_ips = [f"198.51.100.{n}" for n in range(10, 20)]
        run_spray(args.attempts, ip_pool=spray_ips, delay=args.delay, compressed=args.compressed)
