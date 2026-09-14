"""
normal_traffic.py

Simulates a real user checking their mail: occasional logins, human-like
random delays, mostly correct credentials (people fat-finger passwords
sometimes too - so we allow a small natural failure rate).
"""

import socket
import random
import time
import argparse

HOST = "127.0.0.1"
PORT = 9999

REAL_USERS = [
    ("priya.sharma", "Sunshine2024!"),
    ("rahul.verma", "Cricket#99"),
]


def send_attempt(ip, username, password, label="NORMAL", sim_ts=None, real_delay=0.0):
    msg = f"IP:{ip}\nUSER:{username}\nPASS:{password}\nLABEL:{label}\n"
    if sim_ts is not None:
        msg += f"TS:{sim_ts}\n"
    try:
        with socket.create_connection((HOST, PORT), timeout=3) as s:
            s.sendall(msg.encode())
            resp = s.recv(64).decode().strip()
        if real_delay:
            time.sleep(real_delay)
        return resp
    except ConnectionRefusedError:
        print("[normal_traffic] Server not running. Start server.py first.")
        raise


def run(duration_seconds: int, source_ip: str, compressed: bool = False, sim_span_seconds: int = None, demo: bool = False):
    """
    compressed=False, demo=False : real-time mode, realistic pacing (5-120s
        gaps) - what a genuine user looks like.
    demo=True  : real-time mode but faster pacing (2-8s gaps), so a GUI/
        live demo doesn't sit idle for a minute waiting for the next login.
    compressed=True : dataset-generation mode (see below).
    """
    username, password = random.choice(REAL_USERS)

    if not compressed:
        gap_range = (2, 8) if demo else (5, 120)
        mode_name = "DEMO" if demo else "LIVE"
        print(f"[normal_traffic] {mode_name} mode: simulating a normal user for {duration_seconds}s from {source_ip}")
        end_time = time.time() + duration_seconds
        while time.time() < end_time:
            pwd = password if random.random() > 0.05 else password + "x"
            resp = send_attempt(source_ip, username, pwd, label="NORMAL")
            print(f"[normal_traffic] login attempt -> {resp}")
            time.sleep(random.uniform(*gap_range))
    else:
        span = sim_span_seconds or duration_seconds
        print(f"[normal_traffic] COMPRESSED mode: generating {span}s of simulated normal activity from {source_ip}")
        sim_clock = time.time() - span  # start span seconds "in the past"
        end_clock = time.time()
        while sim_clock < end_clock:
            pwd = password if random.random() > 0.05 else password + "x"
            send_attempt(source_ip, username, pwd, label="NORMAL", sim_ts=sim_clock)
            sim_clock += random.uniform(5, 120)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=120, help="seconds to run (live mode)")
    parser.add_argument("--ip", type=str, default="10.0.0.15", help="simulated source ip")
    parser.add_argument("--compressed", action="store_true", help="dataset-generation mode")
    parser.add_argument("--sim-span", type=int, default=3600, help="simulated seconds of activity (compressed mode)")
    parser.add_argument("--demo", action="store_true", help="faster pacing for live GUI demos")
    args = parser.parse_args()
    run(args.duration, args.ip, compressed=args.compressed, sim_span_seconds=args.sim_span, demo=args.demo)
