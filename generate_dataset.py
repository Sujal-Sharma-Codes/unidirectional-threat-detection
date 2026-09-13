"""
generate_dataset.py
Runs many rounds of compressed normal + attack traffic against the mock
server to build a sizeable, labeled, self-generated dataset - replacing
CICIDS2017 entirely.

This is what answers the judges' "not just an existing dataset" feedback:
every row in logs/login_attempts.csv came from traffic we defined and
generated ourselves, with realistic (if time-compressed) timing patterns.
"""
import subprocess
import sys
import random
import os

PY = sys.executable
DIR = os.path.dirname(__file__)

NORMAL_IPS = [f"10.0.0.{n}" for n in (15, 22, 31, 44, 58, 63, 71, 89)]
ATTACKER_IPS = [f"203.0.113.{n}" for n in (10, 24, 77, 91, 105)]


def run(cmd):
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=DIR, check=True)


def main():
    random.seed(42)

    # --- Normal traffic: several "users", each active over a simulated
    #     multi-hour window, to build a solid NORMAL baseline. ---
    for ip in NORMAL_IPS:
        span = random.randint(3600, 3 * 3600)  # 1-3 simulated hours per user
        run([PY, "normal_traffic.py", "--compressed", "--ip", ip, "--sim-span", str(span)])

    # --- Brute force: many separate short bursts at random times, since a
    #     real burst finishes in seconds and would otherwise collapse into a
    #     single time window. Multiple sessions per attacker (re-attempting
    #     over a longer period) gives the model more varied examples. ---
    for ip in ATTACKER_IPS:
        n_sessions = random.randint(4, 8)
        for _ in range(n_sessions):
            n = random.randint(15, 80)
            run([PY, "attack_traffic.py", "--mode", "bruteforce", "--attempts", str(n),
                 "--compressed", "--source-ip", ip])

    # --- Credential spray: several campaigns, each spread across the IP pool ---
    for _ in range(12):
        n = random.randint(40, 200)
        run([PY, "attack_traffic.py", "--mode", "spray", "--attempts", str(n), "--compressed"])

    print("\n[generate_dataset] done. Inspect logs/login_attempts.csv")


if __name__ == "__main__":
    main()
