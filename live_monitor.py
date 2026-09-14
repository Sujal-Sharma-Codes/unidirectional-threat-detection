"""
live_monitor.py

THE DEMO. Watches login_attempts.csv as it grows (like tailing a live log),
maintains a rolling window of recent attempts per source_ip, and classifies
each source_ip as NORMAL or ATTACK in real time using the trained model -
no dataset replay, no held-out rows, just live incoming attempts.

Run this alongside server.py while normal_traffic.py and attack_traffic.py
(in LIVE, non-compressed mode) are generating real traffic, and watch it
flag the attack as it happens.

--- Dashboard integration note ---
This file's detection logic (classify_source, _features_from_window,
_evidence) is unchanged from the original. What was added, to expose the
same real results to the web dashboard without creating a second detection
engine:
  1. Model loading moved out of module-import time and into load_model(),
     so importing this file (e.g. from app.py) doesn't crash the whole
     process if network_threat_model.pkl hasn't been trained yet. The
     dashboard can show a clear "model not loaded" state instead of
     dying on startup.
  2. A threading.Event lets the monitor loop be started/stopped from the
     dashboard's "Start monitoring" / "Stop monitoring" controls, instead
     of only exiting on Ctrl+C.
  3. Every classification result that the loop already computes is also
     handed to event_bus.publish() - the exact same `result` dict that
     _print_result() prints to the terminal. Terminal output is untouched.
"""

import time
import threading
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict, deque

from feature_extractor import FEATURE_COLS
import event_bus

LOG_PATH = "logs/login_attempts.csv"
MODEL_PATH = "network_threat_model.pkl"
FEATURES_PATH = "network_features.pkl"

ROLLING_WINDOW_SECONDS = 60
POLL_INTERVAL_SECONDS = 1
MAX_ATTEMPTS_PER_IP = 500  # ring buffer cap per source ip

# --- model loading (lazy - see module docstring) ----------------------------
_clf = None
_feature_cols = None
_model_load_error = None
_model_lock = threading.Lock()


def is_model_loaded() -> bool:
    return _clf is not None


def get_model_error():
    return _model_load_error


def load_model(force: bool = False):
    """Load the trained Random Forest + its feature column list. Safe to
    call repeatedly (e.g. dashboard "retry" button) - only actually loads
    once unless force=True or the previous attempt failed."""
    global _clf, _feature_cols, _model_load_error
    with _model_lock:
        if _clf is not None and not force:
            return True, None
        try:
            _clf = joblib.load(MODEL_PATH)
            _feature_cols = joblib.load(FEATURES_PATH)
            _model_load_error = None
            return True, None
        except FileNotFoundError:
            _clf = None
            _model_load_error = (
                f"Model file not found ({MODEL_PATH} / {FEATURES_PATH}). "
                f"Run: python3 generate_dataset.py && python3 feature_extractor.py "
                f"&& python3 train_model.py"
            )
            return False, _model_load_error
        except Exception as e:  # pragma: no cover - defensive
            _clf = None
            _model_load_error = f"Failed to load model: {e}"
            return False, _model_load_error


# per-source-ip ring buffer of recent (timestamp, username, payload_size)
_history = defaultdict(lambda: deque(maxlen=MAX_ATTEMPTS_PER_IP))
_last_alert_state = {}  # source_ip -> last classification, to only print on change

# --- monitor loop control ----------------------------------------------------
_stop_event = threading.Event()
_monitor_state_lock = threading.Lock()
_monitor_running = False
_events_seen = 0  # raw CSV rows processed since process start


def is_monitor_running() -> bool:
    with _monitor_state_lock:
        return _monitor_running


def request_stop():
    _stop_event.set()


def get_raw_events_seen() -> int:
    return _events_seen


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


def _pattern_hint(feat: dict) -> str:
    """Display-only heuristic label, NOT a model output. The trained
    classifier is binary (NORMAL/ATTACK) - it does not predict attack
    sub-type. This reuses the exact same thresholds _evidence() already
    checks to describe which of the two attack shapes attack_traffic.py
    implements (brute force / credential spray) the current window most
    resembles, so the dashboard can show something more specific than
    "ATTACK" without claiming the model classifies sub-types it doesn't."""
    if feat["unique_usernames_in_window"] >= 4:
        return "Credential Spray (pattern match)"
    if feat["min_interarrival_sec"] < 1.0 and feat["attempts_in_window"] >= 5:
        return "Brute Force (pattern match)"
    return "Unclassified Attack Pattern"


def classify_source(source_ip: str) -> dict:
    if _clf is None:
        raise RuntimeError("Model not loaded - call load_model() first.")

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


def _publish_event(result: dict):
    """Hand the real classification result to event_bus so the dashboard's
    SSE stream and REST snapshot see exactly what the terminal sees -
    same dict, just relayed. No extra detection happens here."""
    event = {
        "timestamp": time.time(),
        "source_ip": result["source_ip"],
        "event_type": "Login Attempts",
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "risk": result["risk"],
        "evidence": result["evidence"],
        "features": result["features"],
    }
    if result["prediction"] == "ATTACK":
        event["pattern_hint"] = _pattern_hint(result["features"])
    event_bus.publish(event)


def tail_and_monitor():
    """Original polling loop, now stoppable via _stop_event and publishing
    each real result to event_bus in addition to the terminal."""
    global _monitor_running, _events_seen

    print(f"[live_monitor] watching {LOG_PATH} (poll every {POLL_INTERVAL_SECONDS}s, "
          f"rolling window {ROLLING_WINDOW_SECONDS}s)")

    with _monitor_state_lock:
        _monitor_running = True
    _stop_event.clear()

    last_size = 0
    try:
        while not _stop_event.is_set():
            try:
                df = pd.read_csv(LOG_PATH)
            except (FileNotFoundError, pd.errors.EmptyDataError):
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            if len(df) > last_size:
                new_rows = df.iloc[last_size:]
                last_size = len(df)
                _events_seen = last_size

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

                    # Dashboard sees every real classification for a
                    # touched IP, not just state changes, so the live feed
                    # reflects actual traffic volume.
                    _publish_event(result)

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[live_monitor] stopped")
    finally:
        with _monitor_state_lock:
            _monitor_running = False


def run_monitor_loop():
    """Thread target used by app.py. Loads the model first; if that fails,
    logs the error and returns without starting the loop (does not crash
    the Flask process)."""
    ok, err = load_model()
    if not ok:
        print(f"[live_monitor] cannot start: {err}")
        return
    tail_and_monitor()


def _print_result(result: dict):
    tag = "🚨 ATTACK" if result["prediction"] == "ATTACK" else "✅ normal"
    print(f"\n[{time.strftime('%H:%M:%S')}] {tag} source={result['source_ip']} "
          f"risk={result['risk']} confidence={result['confidence']*100:.1f}%")
    for e in result["evidence"]:
        print(f"   - {e}")


if __name__ == "__main__":
    ok, err = load_model()
    if not ok:
        print(f"[live_monitor] {err}")
        raise SystemExit(1)
    tail_and_monitor()
