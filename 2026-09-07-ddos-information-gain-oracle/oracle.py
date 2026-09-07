#!/usr/bin/env python3
"""Offline CICDDoS2019 experiment; uniformly sample each complete CSV."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text

FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "SYN Flag Count", "ACK Flag Count", "Packet Length Mean"]


def sample_file(path, cap, seed):
    rng = np.random.default_rng(seed)
    kept = pd.DataFrame()
    counts = {}
    scanned = 0
    for chunk in pd.read_csv(path, usecols=lambda c: c.strip() in FEATURES + ["Label"],
                             chunksize=100000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        labels = chunk["Label"].astype("string").str.strip()
        for label, n in labels.fillna("<missing>").value_counts().items():
            counts[str(label)] = counts.get(str(label), 0) + int(n)
        scanned += len(chunk)
        valid = labels.notna() & labels.ne("")
        chunk = chunk.loc[valid].copy()
        chunk["Label"] = labels.loc[valid]
        chunk["priority"] = rng.random(len(chunk))
        kept = pd.concat([kept, chunk], ignore_index=True).nsmallest(cap, "priority")
    if kept.empty:
        raise ValueError(f"No labelled rows: {path}")
    x = kept[FEATURES].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    x[~np.isfinite(x)] = np.nan
    y = kept["Label"].str.upper().ne("BENIGN").to_numpy(dtype=int)
    return x, y, {"file": path.name, "scanned": scanned, "labels": counts,
                  "sample": len(y), "sample_benign": int((y == 0).sum())}


def rate(a, b):
    return float(a / b) if b else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("data", type=Path)
    parser.add_argument("--cap", type=int, default=12000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", type=Path, default=Path("oracle-results.json"))
    args = parser.parse_args()
    if args.cap < 1:
        parser.error("--cap must be positive")
    files = sorted(args.data.glob("*.csv"))
    if len(files) < 2:
        parser.error("Need at least two CSV files")
    samples = []
    inventory = []
    for i, path in enumerate(files):
        x, y, info = sample_file(path, args.cap, args.seed + i)
        samples.append((x, y))
        inventory.append(info)
        print(json.dumps(info), flush=True)
    results = []
    for held, path in enumerate(files):
        train_x = np.concatenate([s[0] for i, s in enumerate(samples) if i != held])
        train_y = np.concatenate([s[1] for i, s in enumerate(samples) if i != held])
        if len(np.unique(train_y)) != 2:
            raise ValueError("Training fold needs both benign and attack rows")
        # Train-only imputation; no global quantiles or identifiers.
        medians = np.nanmedian(train_x, axis=0)
        medians = np.nan_to_num(medians, nan=0.0)
        train_x = np.where(np.isnan(train_x), medians, train_x)
        test_x, test_y = samples[held]
        test_x = np.where(np.isnan(test_x), medians, test_x)
        for depth in [0, 1, 2, 4, 8]:
            if depth == 0:
                pred = np.full(len(test_y), int(train_y.mean() >= 0.5))
                questions = np.zeros(len(test_y))
            else:
                model = DecisionTreeClassifier(criterion="entropy", max_depth=depth,
                                               min_samples_leaf=100, random_state=args.seed)
                model.fit(train_x, train_y)
                pred = model.predict(test_x)
                questions = np.diff(model.decision_path(test_x).indptr) - 1
                if held == 0 and depth == 2:
                    print(export_text(model, feature_names=FEATURES), flush=True)
            tn = int(((test_y == 0) & (pred == 0)).sum())
            fp = int(((test_y == 0) & (pred == 1)).sum())
            fn = int(((test_y == 1) & (pred == 0)).sum())
            tp = int(((test_y == 1) & (pred == 1)).sum())
            results.append(dict(file=path.name, depth=depth, tn=tn, fp=fp, fn=fn, tp=tp,
                                fpr=rate(fp, fp + tn), recall=rate(tp, tp + fn),
                                precision=rate(tp, tp + fp),
                                mean_questions=float(questions.mean())))
    args.output.write_text(json.dumps({"seed": args.seed, "cap": args.cap,
                                      "features": FEATURES, "inventory": inventory,
                                      "results": results}, indent=2) + "\n")
    for depth in [0, 1, 2, 4, 8]:
        rows = [r for r in results if r["depth"] == depth]
        counts = {k: sum(r[k] for r in rows) for k in ["tn", "fp", "fn", "tp"]}
        print(json.dumps(dict(depth=depth, **counts,
                              fpr=rate(counts["fp"], counts["fp"] + counts["tn"]),
                              recall=rate(counts["tp"], counts["tp"] + counts["fn"]))))


if __name__ == "__main__":
    main()
