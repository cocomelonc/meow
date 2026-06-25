#!/usr/bin/env python3
import csv

import matplotlib.pyplot as plt


def read_csv(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "t": int(row["t"]),
                "value": float(row["value"]),
                "label": int(row["label"]),
                "rolling_avg": float(row["rolling_avg"]),
                "db4_detail": float(row["db4_detail"]),
                "db4_score": float(row["db4_score"]),
                "avg_alert": int(row["avg_alert"]),
                "db4_alert": int(row["db4_alert"]),
            })
    return rows


EVENT_GRACE = 3


def event_metrics(rows, alert_key):
    tp = fp = fn = events = 0
    covered = [False] * len(rows)

    i = 0
    while i < len(rows):
        if not rows[i]["label"]:
            i += 1
            continue

        start = i
        while i < len(rows) and rows[i]["label"]:
            i += 1
        end = i - 1
        grace_end = min(len(rows) - 1, end + EVENT_GRACE)

        detected = False
        for j in range(start, grace_end + 1):
            covered[j] = True
            if rows[j][alert_key]:
                detected = True

        events += 1
        if detected:
            tp += 1
        else:
            fn += 1

    for i, row in enumerate(rows):
        if row[alert_key] and not covered[i]:
            fp += 1

    return tp, fp, fn, events


def main():
    rows = read_csv("db4_results.csv")

    t = [r["t"] for r in rows]
    value = [r["value"] for r in rows]
    rolling = [r["rolling_avg"] for r in rows]
    score = [r["db4_score"] for r in rows]

    attack_t = [r["t"] for r in rows if r["label"]]
    attack_y = [r["value"] for r in rows if r["label"]]

    alert_t = [r["t"] for r in rows if r["db4_alert"]]
    alert_y = [r["db4_score"] for r in rows if r["db4_alert"]]

    avg_tp, avg_fp, avg_fn, _ = event_metrics(rows, "avg_alert")
    db4_tp, db4_fp, db4_fn, _ = event_metrics(rows, "db4_alert")

    fig, axes = plt.subplots(3, 1, figsize=(12, 10))

    axes[0].plot(t, value, label="traffic feature", color="#1f77b4", linewidth=1.6)
    axes[0].plot(t, rolling, label="rolling average", color="#ff7f0e", linewidth=1.4)
    axes[0].axhline(600.0, color="#d62728", linestyle="--", linewidth=1.1, label="average threshold")
    axes[0].scatter(attack_t, attack_y, color="#d62728", s=18, label="attack label", zorder=5)
    axes[0].set_title("CICDDoS2019-style time series: short attack events")
    axes[0].set_ylabel("aggregated flow feature")
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(loc="upper right")

    axes[1].plot(t, score, label="Daubechies D4 detail robust z-score", color="#2ca02c", linewidth=1.5)
    axes[1].axhline(8.0, color="#d62728", linestyle="--", linewidth=1.1, label="D4 threshold")
    axes[1].scatter(alert_t, alert_y, color="#d62728", s=20, label="D4 alerts", zorder=5)
    axes[1].set_title("D4 wavelet detects sharp multi-sample changes")
    axes[1].set_ylabel("robust z-score")
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(loc="upper right")

    names = ["TP", "FP", "FN"]
    avg_values = [avg_tp, avg_fp, avg_fn]
    db4_values = [db4_tp, db4_fp, db4_fn]
    x = range(len(names))
    axes[2].bar([i - 0.18 for i in x], avg_values, width=0.36, label="rolling average", color="#ff7f0e")
    axes[2].bar([i + 0.18 for i in x], db4_values, width=0.36, label="Daubechies D4", color="#2ca02c")
    axes[2].set_xticks(list(x))
    axes[2].set_xticklabels(names)
    axes[2].set_title("Event-level detector comparison")
    axes[2].set_ylabel("events")
    axes[2].grid(True, axis="y", alpha=0.25)
    axes[2].legend(loc="upper right")

    fig.tight_layout()
    fig.savefig("db4_detection.png", dpi=160)
    print("wrote db4_detection.png")


if __name__ == "__main__":
    main()
