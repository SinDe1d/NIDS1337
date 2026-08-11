#!/usr/bin/env python3
"""Train and compare two scikit-learn classifiers.

With no CSV supplied, a deterministic demo dataset is generated so the project
works immediately. For CICIDS2017/UNSW-NB15, pass --csv and --label-column.
The loader maps common feature names and fills missing columns with zero.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from nids.features import FEATURE_NAMES


def demo_dataset(seed: int = 1337, rows_per_class: int = 80):
    rng = np.random.default_rng(seed)
    rows, labels = [], []
    for label in ["Benign", "Port Scan", "SYN flood", "Brute Force"]:
        for _ in range(rows_per_class):
            row = {name: 0.0 for name in FEATURE_NAMES}
            row["duration"] = float(rng.uniform(0.02, 5.0))
            row["total_fwd_packets"] = float(rng.integers(1, 10))
            row["total_bwd_packets"] = float(rng.integers(0, 10))
            row["total_fwd_bytes"] = float(rng.integers(40, 3000))
            row["total_bwd_bytes"] = float(rng.integers(0, 5000))
            row["packet_size_mean"] = float(rng.uniform(50, 900))
            row["packet_size_std"] = float(rng.uniform(0, 300))
            row["packet_size_min"] = float(rng.uniform(40, 100))
            row["packet_size_max"] = float(rng.uniform(300, 1500))
            row["iat_mean"] = float(rng.uniform(0.001, 1.0))
            row["iat_std"] = float(rng.uniform(0.001, 0.5))
            row["iat_min"] = float(rng.uniform(0.0001, 0.1))
            row["iat_max"] = float(rng.uniform(0.1, 1.5))
            row["syn_count"] = float(rng.integers(0, 3))
            row["ack_count"] = float(rng.integers(0, 8))
            row["fin_count"] = float(rng.integers(0, 2))
            row["rst_count"] = float(rng.integers(0, 2))
            row["psh_count"] = float(rng.integers(0, 4))
            row["flow_packets_per_second"] = float(rng.uniform(1, 30))
            if label == "Port Scan":
                row.update(syn_count=1, total_bwd_packets=0, total_fwd_packets=rng.integers(1, 3),
                           rst_count=rng.integers(1, 3), flow_packets_per_second=rng.uniform(30, 100))
            elif label == "SYN flood":
                row.update(syn_count=rng.integers(5, 50), total_bwd_packets=0,
                           flow_packets_per_second=rng.uniform(40, 300))
            elif label == "Brute Force":
                row.update(total_fwd_packets=rng.integers(10, 60), total_bwd_packets=rng.integers(2, 10),
                           rst_count=rng.integers(1, 5), flow_packets_per_second=rng.uniform(20, 100))
            rows.append([row[name] for name in FEATURE_NAMES])
            labels.append(label)
    return np.asarray(rows, dtype=float), np.asarray(labels)


ALIASES = {
    "flow duration": "duration", "duration": "duration",
    "tot fwd pkts": "total_fwd_packets", "total fwd packets": "total_fwd_packets",
    "tot bwd pkts": "total_bwd_packets", "total backward packets": "total_bwd_packets",
    "totlen fwd pkts": "total_fwd_bytes", "total length of fwd packets": "total_fwd_bytes",
    "totlen bwd pkts": "total_bwd_bytes", "total length of bwd packets": "total_bwd_bytes",
    "fwd pkt len mean": "fwd_packet_size_mean", "bwd pkt len mean": "bwd_packet_size_mean",
    "packet length mean": "packet_size_mean", "packet length std": "packet_size_std",
    "flow bytes/s": "flow_bytes_per_second", "flow packets/s": "flow_packets_per_second",
}


def csv_dataset(path: str, label_column: str):
    with open(path, newline="", encoding="utf-8-sig", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        rows, labels = [], []
        normalized = {key.strip().lower(): key for key in reader.fieldnames or []}
        label_key = normalized.get(label_column.lower(), label_column)
        for raw in reader:
            mapping = {}
            for name in FEATURE_NAMES:
                source = normalized.get(name.lower())
                if source is None:
                    source = next((key for key in raw if ALIASES.get(key.strip().lower()) == name), None)
                try:
                    mapping[name] = float(str(raw.get(source, "0")).replace(",", "").strip() or 0)
                except ValueError:
                    mapping[name] = 0.0
            rows.append([mapping[name] for name in FEATURE_NAMES])
            labels.append(raw.get(label_key, "Benign").strip() or "Benign")
    return np.asarray(rows), np.asarray(labels)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--output", default="models/nids_model.joblib")
    parser.add_argument("--metrics", default="models/metrics.json")
    args = parser.parse_args()
    X, y = csv_dataset(args.csv, args.label_column) if args.csv else demo_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    models = {
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=180, random_state=42, class_weight="balanced", n_jobs=-1
        ),
    }
    results = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        results[name] = {
            "macro_f1": float(f1_score(y_test, predictions, average="macro")),
            "classification_report": classification_report(y_test, predictions, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
            "labels": sorted(set(y_test)),
        }
    best_name = max(results, key=lambda key: results[key]["macro_f1"])
    best = models[best_name]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(best, args.output)
    Path(args.metrics).write_text(json.dumps({
        "dataset": args.csv or "built-in deterministic demo dataset",
        "rows": int(len(y)), "features": FEATURE_NAMES,
        "models": results, "selected_model": best_name,
    }, indent=2))
    print(json.dumps({
        "rows": len(y), "selected_model": best_name,
        "macro_f1": results[best_name]["macro_f1"],
        "model": args.output, "metrics": args.metrics,
    }, indent=2))


if __name__ == "__main__":
    main()
