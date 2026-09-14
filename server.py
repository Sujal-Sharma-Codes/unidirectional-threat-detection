"""
server.py

A minimal mock mail-login server (mimics an IMAP/SMTP AUTH LOGIN exchange).

Why this exists:
Instead of training on a static, years-old dataset (CICIDS2017), we build
our own live, labeled dataset from traffic we generate ourselves. This
server is the "sensor point" - every incoming login attempt is logged.

Protocol (simple line-based, not real IMAP - kept minimal on purpose):
    Client connects and sends:
        IP:<fake_source_ip>
        USER:<username>
        PASS:<password>
        LABEL:<NORMAL|ATTACK_BRUTEFORCE|ATTACK_SPRAY>   (ground-truth tag,
            used ONLY to build training labels - a real detector would never
            have this, since IDS doesn't see the attacker's intent)
        TS:<simulated_unix_timestamp>   (optional - lets the dataset
            generator compress hours/days of realistic timing into seconds
            of actual wall-clock run time; if omitted, real time.time() is
            used, which is what the live demo will do)

    Server replies "OK\n" or "FAIL\n" and closes the connection.

Every attempt is appended to logs/login_attempts.csv with:
    timestamp, source_ip, username, success, payload_size, true_label

Note on the "unidirectional" theme: the detector we build later will NOT use
the server's response (success/fail requires a round trip in a real network,
but here it's a natural side-effect of the login server itself, not a
response-flow feature). To stay faithful to the one-way-visibility
constraint, our feature extractor (Step 3) will deliberately drop
`success` from the feature set and keep only what an inbound-only sensor
could see: arrival timing, payload size, username patterns.
"""

import socket
import threading
import csv
import os
import time

HOST = "127.0.0.1"
PORT = 9999
LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "login_attempts.csv")

# A tiny fake user database for realism (username -> password)
VALID_USERS = {
    "priya.sharma": "Sunshine2024!",
    "rahul.verma": "Cricket#99",
}

_lock = threading.Lock()


def _ensure_log_header():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            csv.writer(f).writerow(
                ["timestamp", "source_ip", "username", "success", "payload_size", "true_label"]
            )


def _log_attempt(source_ip, username, success, payload_size, true_label, ts):
    with _lock:
        with open(LOG_PATH, "a", newline="") as f:
            csv.writer(f).writerow(
                [ts, source_ip, username, int(success), payload_size, true_label]
            )


def _parse_message(raw: str):
    fields = {}
    for line in raw.strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().upper()] = v.strip()
    return fields


def _handle_client(conn, addr):
    try:
        data = conn.recv(4096)
        raw = data.decode(errors="ignore")
        fields = _parse_message(raw)

        source_ip = fields.get("IP", addr[0])
        username = fields.get("USER", "")
        password = fields.get("PASS", "")
        true_label = fields.get("LABEL", "NORMAL")
        sim_ts = fields.get("TS")
        ts = float(sim_ts) if sim_ts else time.time()

        success = VALID_USERS.get(username) == password
        _log_attempt(source_ip, username, success, len(data), true_label, ts)

        conn.sendall(b"OK\n" if success else b"FAIL\n")
    except Exception as e:
        print(f"[server] error handling {addr}: {e}")
    finally:
        conn.close()


def run_server():
    _ensure_log_header()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    print(f"[server] mock login server listening on {HOST}:{PORT}")
    print(f"[server] logging attempts to {LOG_PATH}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[server] shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    run_server()
