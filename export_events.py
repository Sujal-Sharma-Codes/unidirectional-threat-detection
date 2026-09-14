"""
export_events.py
Runs the REAL trained model (network_threat_model.pkl) over a chosen
traffic log and exports a JSON events file for dashboard.html to replay.

This is the bridge between the working detection engine and the GUI: the
dashboard never re-implements detection logic in JavaScript, it only
visualizes exactly what this script - and therefore the actual model -
decided.

Usage:
    python3 export_events.py --raw logs/login_attempts.csv --out dashboard_events.json
    python3 export_events.py --raw path/to/some_other_capture.csv --out other_events.json

You can point --raw at any CSV with the same columns your server.py logs
(timestamp, source_ip, username, success, payload_size, true_label) - e.g.
a fresh capture from a live demo run, or a scenario you generated
separately. That's the "which file do we run" step: this script is what
you run against a chosen log, and its output is what you load into the
dashboard.
"""
import argparse
import json
from datetime import datetime

import joblib

from feature_extractor import load_raw, extract_features, FEATURE_COLS, WINDOW_SECONDS

MODEL_PATH = "network_threat_model.pkl"
FEATURES_PATH = "network_features.pkl"


def build_events(raw_csv_path: str, out_json_path: str):
    raw = load_raw(raw_csv_path)
    windows = extract_features(raw)

    clf = joblib.load(MODEL_PATH)
    feat_cols = joblib.load(FEATURES_PATH)
    assert feat_cols == FEATURE_COLS, "feature list mismatch between saved model and extractor"

    X = windows[feat_cols].astype("float32")
    proba = clf.predict_proba(X)
    preds = clf.predict(X)
    classes = list(clf.classes_)

    events = []
    for i, row in windows.reset_index(drop=True).iterrows():
        p = proba[i]
        pred = preds[i]
        confidence = float(max(p))

        risk = "NONE"
        if pred == "ATTACK":
            risk = "HIGH" if confidence >= 0.9 else ("MEDIUM" if confidence >= 0.7 else "LOW")

        # Sub-type label for display only - a readable guess at which attack
        # pattern this looks like, based on the same features the model
        # used. The model itself only predicts NORMAL/ATTACK; this is not
        # a separate classifier, just a human-readable annotation.
        if pred == "ATTACK":
            attack_type = "CREDENTIAL SPRAY" if row["unique_usernames_in_window"] >= 3 else "BRUTE FORCE"
        else:
            attack_type = "NORMAL"

        evidence = []
        if row["attempts_in_window"] >= 5:
            evidence.append(
                f"{int(row['attempts_in_window'])} login attempts in a {WINDOW_SECONDS}s window (normal is ~1)"
            )
        if row["min_interarrival_sec"] < 1.0:
            evidence.append(
                f"attempts only {row['min_interarrival_sec']:.2f}s apart - too fast for a human typing a password"
            )
        if row["unique_usernames_in_window"] >= 3:
            evidence.append(
                f"{int(row['unique_usernames_in_window'])} different usernames tried from one source"
            )
        if not evidence and pred == "ATTACK":
            evidence.append("combined feature pattern deviates from normal baseline")

        ts = float(row["window_id"] * WINDOW_SECONDS)
        events.append({
            "timestamp": ts,
            "time_str": datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
            "source_ip": row["source_ip"],
            "prediction": pred,
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "risk": risk,
            "attempts_in_window": int(row["attempts_in_window"]),
            "unique_usernames_in_window": int(row["unique_usernames_in_window"]),
            "window_seconds": WINDOW_SECONDS,
            "evidence": evidence,
        })

    events.sort(key=lambda e: e["timestamp"])

    with open(out_json_path, "w") as f:
        json.dump(events, f, indent=2)

    n_attack = sum(1 for e in events if e["prediction"] == "ATTACK")
    print(f"Wrote {len(events)} events to {out_json_path}  ({n_attack} flagged ATTACK, {len(events)-n_attack} NORMAL)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", default="logs/login_attempts.csv", help="path to a raw login_attempts.csv-style log")
    parser.add_argument("--out", default="dashboard_events.json", help="path to write the events JSON")
    args = parser.parse_args()
    build_events(args.raw, args.out)
