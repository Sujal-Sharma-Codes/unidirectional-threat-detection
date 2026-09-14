"""
feature_extractor.py

Converts raw login_attempts.csv rows into windowed, per-source-IP behavioral
features suitable for training/inference.

Design choice (this is the important part for the "unidirectional" pitch):
We deliberately build every feature from what an INBOUND-ONLY sensor can
observe about the request itself - arrival timing, payload size,
username pattern, request volume. We do NOT use `success` (whether the
login succeeded), even though it's available in our simulation, because
a real one-way sensor sitting in front of the server (e.g. a network tap
or data-diode feed) would not reliably see the full round trip. This
keeps the feature set honest for the unidirectional-visibility scenario,
unlike the original CICIDS2017 model which leaned heavily on `Bwd_*`
(response-direction) flow statistics.

Windowing: attempts from the same source_ip are grouped into fixed-size
tumbling time windows (default 60s). Each window becomes one training row.
Real attacks show up as bursts (many attempts, tight timing) within a
window; real users show up as at most one attempt per window.
"""

import pandas as pd
import numpy as np

WINDOW_SECONDS = 60

FEATURE_COLS = [
    "attempts_in_window",
    "unique_usernames_in_window",
    "mean_interarrival_sec",
    "std_interarrival_sec",
    "min_interarrival_sec",
    "mean_payload_size",
    "std_payload_size",
]


def load_raw(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = df["timestamp"].astype(float)
    return df


def extract_features(df: pd.DataFrame, window_seconds: int = WINDOW_SECONDS) -> pd.DataFrame:
    df = df.copy()
    df["window_id"] = (df["timestamp"] // window_seconds).astype(np.int64)
    df = df.sort_values(["source_ip", "window_id", "timestamp"])

    rows = []
    for (source_ip, window_id), g in df.groupby(["source_ip", "window_id"]):
        g = g.sort_values("timestamp")
        n = len(g)
        usernames = g["username"].nunique()
        payload = g["payload_size"].astype(float)

        if n > 1:
            gaps = g["timestamp"].diff().dropna().values
            mean_gap = float(np.mean(gaps))
            std_gap = float(np.std(gaps))
            min_gap = float(np.min(gaps))
        else:
            # A single attempt in the window looks like normal, sparse
            # behaviour - encode that with a "large gap" sentinel rather
            # than 0/NaN, so the model doesn't confuse "only one attempt"
            # with "attempts fired instantly".
            mean_gap = float(window_seconds)
            std_gap = 0.0
            min_gap = float(window_seconds)

        # majority true_label in this window (ground truth for training only)
        majority_label = g["true_label"].mode().iloc[0]

        rows.append({
            "source_ip": source_ip,
            "window_id": window_id,
            "attempts_in_window": n,
            "unique_usernames_in_window": usernames,
            "mean_interarrival_sec": mean_gap,
            "std_interarrival_sec": std_gap,
            "min_interarrival_sec": min_gap,
            "mean_payload_size": float(payload.mean()),
            "std_payload_size": float(payload.std()) if n > 1 else 0.0,
            "true_label": majority_label,
        })

    out = pd.DataFrame(rows)
    # Binary target: NORMAL vs ATTACK (any type). Keep true_label around too
    # for a bonus multi-class breakdown / richer evidence messages.
    out["binary_label"] = np.where(out["true_label"] == "NORMAL", "NORMAL", "ATTACK")
    return out


if __name__ == "__main__":
    raw = load_raw("logs/login_attempts.csv")
    features = extract_features(raw)
    features.to_csv("logs/windowed_features.csv", index=False)
    print(f"Extracted {len(features)} windows from {len(raw)} raw attempts")
    print(features["binary_label"].value_counts())
    print(features["true_label"].value_counts())
