"""
train_model.py

Trains a Random Forest on the windowed, unidirectional-safe features.

Compare this file's honesty with the original: we report accuracy that will
be noticeably lower than the old CICIDS2017 model's 99.9%. That's expected
and correct - we removed the response-side (Bwd_*) features that were
inflating the old score, and the dataset is much smaller and self-generated.
We report this drop explicitly rather than hiding it, because that's the
actual point being demonstrated.
"""

import pandas as pd
import numpy as np
import json
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)
import time

from feature_extractor import FEATURE_COLS

DATA_PATH = "logs/windowed_features.csv"
MODEL_PATH = "network_threat_model.pkl"
FEATURES_PATH = "network_features.pkl"
RESULTS_PATH = "model_results.json"
IMPORTANCE_PATH = "feature_importance.csv"


def main():
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURE_COLS].astype("float32")
    y = df["binary_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        class_weight="balanced",  # dataset is imbalanced (attacks are rarer)
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    t0 = time.time()
    y_pred = clf.predict(X_test)
    infer_seconds = time.time() - t0

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label="ATTACK")
    rec = recall_score(y_test, y_pred, pos_label="ATTACK")
    f1 = f1_score(y_test, y_pred, pos_label="ATTACK")
    cm = confusion_matrix(y_test, y_pred, labels=["NORMAL", "ATTACK"])
    report = classification_report(y_test, y_pred)

    importances = dict(sorted(
        zip(FEATURE_COLS, clf.feature_importances_.tolist()),
        key=lambda kv: kv[1], reverse=True
    ))

    results = {
        "note": (
            "Unidirectional feature set (no response/Bwd_* features, no "
            "success/fail signal). Self-generated dataset from a mock login "
            "server, not CICIDS2017. Lower accuracy than a bidirectional "
            "model is expected and is reported honestly here."
        ),
        "n_trees": 150,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "n_features": len(FEATURE_COLS),
        "accuracy": round(acc, 4),
        "precision_attack": round(prec, 4),
        "recall_attack": round(rec, 4),
        "f1_attack": round(f1, 4),
        "confusion_matrix_labels": ["NORMAL", "ATTACK"],
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "inference_seconds_for_test_set": round(infer_seconds, 4),
        "per_sample_latency_ms": round(infer_seconds / max(len(X_test), 1) * 1000, 4),
        "feature_importance": importances,
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)

    pd.DataFrame(
        {"feature": list(importances.keys()), "importance": list(importances.values())}
    ).to_csv(IMPORTANCE_PATH, index=False)

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(FEATURE_COLS, FEATURES_PATH)

    print(json.dumps({k: v for k, v in results.items() if k not in ("classification_report",)}, indent=2))
    print("\n" + report)
    print(f"Saved model -> {MODEL_PATH}")
    print(f"Saved feature list -> {FEATURES_PATH}")


if __name__ == "__main__":
    main()
