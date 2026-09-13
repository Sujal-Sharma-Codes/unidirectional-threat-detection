"""
live_monitor.py
THE DEMO. Watches login_attempts.csv as it grows (like tailing a live log),
maintains a rolling window of recent attempts per source_ip, and classifies
each source_ip as NORMAL or ATTACK in real time using the trained model -
no dataset replay, no held-out rows, just live incoming attempts.

Run this alongside server.py while normal_traffic.py and attack_traffic.py
(in LIVE, non-compressed mode) are generating real traffic, and watch it
flag the attack as it happens.
"""
import time
import json
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict, deque

from feature_extractor import FEATURE_COLS

LOG_PATH = "logs/login_attempts.csv"
MODEL_PATH = "network_threat_model.pkl"
FEATURES_PATH = "network_features.pkl"
ROLLING_WINDOW_SECONDS = 60
POLL_INTERVAL_SECONDS = 1
MAX_ATTEMPTS_PER_IP = 500  # ring buffer cap per source ip

_clf = joblib.load(MODEL_PATH)
_feature_cols = joblib.load(FEATURES_PATH)

# per-source-ip ring buffer of recent (timestamp, username, payload_size)
_history = defaultdict(lambda: deque(maxlen=MAX_ATTEMPTS_PER_IP))
_last_alert_state = {}  # source_ip -> last classification, to only print on change


def _features_from_window(records):
    """records: list of (timestamp, username, payload_size), same shape as
    feature_extractor.extract_features but computed live on a rolling window
    instead of a fixed historical bucket."""
    n = len(records)
    timestamps = [r[0] for r in records]
    usernames = {r[1] for r in records}
    payloads = np.array([r[2] for r in records], dtype=float)

    if n > 1:
        gaps = np.diff(sorted(timestamps))
        mean_gap = float(np.mean(gaps))
        std_gap = float(np.std(gaps))
        min_gap = float(np.min(gaps))
    else:
        mean_gap = float(ROLLING_WINDOW_SECONDS)
        std_gap = 0.0
        min_gap = float(ROLLING_WINDOW_SECONDS)

    return {
        "attempts_in_window": n,
        "unique_usernames_in_window": len(usernames),
        "mean_interarrival_sec": mean_gap,
        "std_interarrival_sec": std_gap,
        "min_interarrival_sec": min_gap,
        "mean_payload_size": float(payloads.mean()),
        "std_payload_size": float(payloads.std()) if n > 1 else 0.0,
    }


def _evidence(feat: dict, pred: str) -> list:
    """Human-readable reasons, same spirit as the original evidence
    generator: which features look unusual and by how much."""
    baseline = {
        "attempts_in_window": 1,
        "mean_interarrival_sec": 45,
        "min_interarrival_sec": 45,
        "unique_usernames_in_window": 1,
    }
    notes = []
    if feat["attempts_in_window"] >= 5:
        notes.append(f"{feat['attempts_in_window']} login attempts in the last "
                      f"{ROLLING_WINDOW_SECONDS}s from this source (normal is ~1)")
    if feat["min_interarrival_sec"] < 1.0:
        notes.append(f"attempts arriving only {feat['min_interarrival_sec']:.2f}s apart "
                      f"(no human types a password that fast, repeatedly)")
    if feat["unique_usernames_in_window"] >= 4:
        notes.append(f"{feat['unique_usernames_in_window']} different usernames tried "
                      f"from one source (credential spray pattern)")
    if not notes and pred == "ATTACK":
        notes.append("combined pattern across features looks anomalous")
    return notes[:4]


def classify_source(source_ip: str) -> dict:
    records = list(_history[source_ip])
    now = time.time()
    window_records = [r for r in records if now - r[0] <= ROLLING_WINDOW_SECONDS]
    if not window_records:
        return None

    feat = _features_from_window(window_records)
    X = pd.DataFrame([feat])[_feature_cols].astype("float32")
    proba = _clf.predict_proba(X)[0]
    classes = list(_clf.classes_)
    pred = classes[int(np.argmax(proba))]
    confidence = float(np.max(proba))
    risk = "NONE"
    if pred == "ATTACK":
        risk = "HIGH" if confidence >= 0.9 else ("MEDIUM" if confidence >= 0.7 else "LOW")

    return {
        "source_ip": source_ip,
        "prediction": pred,
        "confidence": round(confidence, 3),
        "risk": risk,
        "evidence": _evidence(feat, pred),
        "features": feat,
    }


def tail_and_monitor():
    print(f"[live_monitor] watching {LOG_PATH} (poll every {POLL_INTERVAL_SECONDS}s, "
          f"rolling window {ROLLING_WINDOW_SECONDS}s)")
    last_size = 0
    try:
        while True:
            try:
                df = pd.read_csv(LOG_PATH)
            except (FileNotFoundError, pd.errors.EmptyDataError):
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            if len(df) > last_size:
                new_rows = df.iloc[last_size:]
                last_size = len(df)
                touched_ips = set()
                for _, row in new_rows.iterrows():
                    ip = row["source_ip"]
                    _history[ip].append((float(row["timestamp"]), row["username"], float(row["payload_size"])))
                    touched_ips.add(ip)

                for ip in touched_ips:
                    result = classify_source(ip)
                    if result is None:
                        continue
                    state_key = (result["prediction"], result["risk"])
                    if _last_alert_state.get(ip) != state_key:
                        _last_alert_state[ip] = state_key
                        _print_result(result)

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[live_monitor] stopped")


def _print_result(result: dict):
    tag = "🚨 ATTACK" if result["prediction"] == "ATTACK" else "✅ normal"
    print(f"\n[{time.strftime('%H:%M:%S')}] {tag}  source={result['source_ip']}  "
          f"risk={result['risk']}  confidence={result['confidence']*100:.1f}%")
    for e in result["evidence"]:
        print(f"    - {e}")


if __name__ == "__main__":
    tail_and_monitor()
