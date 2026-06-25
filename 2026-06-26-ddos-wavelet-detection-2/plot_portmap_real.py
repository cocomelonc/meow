#!/usr/bin/env python3
# author @cocomelonc
import csv

import matplotlib.pyplot as plt


EVENT_MERGE_GAP = 5
EVENT_GRACE = 3


def read_csv(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "t": int(row["t"]),
                "value": float(row["value"]),
                "label": int(row["label"]),
                "rolling_avg": float(row["rolling_avg"]),
                "avg_score": float(row["avg_score"]),
                "db4_detail": float(row["db4_detail"]),
                "db4_score": float(row["db4_score"]),
                "avg_alert": int(row["avg_alert"]),
                "db4_alert": int(row["db4_alert"]),
            })
    return rows


def event_metrics(rows, alert_key):
    tp = fp = fn = events = 0
    covered = [False] * len(rows)

    i = 0
    while i < len(rows):
        if not rows[i]["label"]:
            i += 1
            continue

        start = i
        end = i
        last_attack = i
        i += 1
        while i < len(rows):
            if rows[i]["label"]:
                last_attack = i
                end = i
                i += 1
                continue
            if i - last_attack <= EVENT_MERGE_GAP:
                end = i
                i += 1
                continue
            break

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


def first_large_attack_window(rows):
    labels = [r["label"] for r in rows]
    best_start = 0
    best_count = -1
    width = 220
    for i in range(0, max(1, len(rows) - width)):
        c = sum(labels[i:i + width])
        if c > best_count:
            best_count = c
            best_start = i
    return best_start, min(len(rows), best_start + width)


def main():
    rows = read_csv("portmap_real_results.csv")
    t = [r["t"] for r in rows]
    value = [r["value"] for r in rows]
    rolling = [r["rolling_avg"] for r in rows]
    avg_score = [r["avg_score"] for r in rows]
    db4_score = [r["db4_score"] for r in rows]

    attack_t = [r["t"] for r in rows if r["label"]]
    attack_y = [r["value"] for r in rows if r["label"]]
    db4_alert_t = [r["t"] for r in rows if r["db4_alert"]]
    db4_alert_y = [r["db4_score"] for r in rows if r["db4_alert"]]

    avg_tp, avg_fp, avg_fn, _ = event_metrics(rows, "avg_alert")
    db4_tp, db4_fp, db4_fn, _ = event_metrics(rows, "db4_alert")

    zoom_start, zoom_end = first_large_attack_window(rows)
    zr = rows[zoom_start:zoom_end]

    fig, axes = plt.subplots(4, 1, figsize=(13, 13))

    axes[0].plot(t, value, label="Portmap flows/sec", color="#1f77b4", linewidth=1.3)
    axes[0].scatter(attack_t, attack_y, color="#d62728", s=8, label="Portmap label", zorder=4)
    axes[0].set_title("CICDDoS2019 03-11 Portmap.csv: real aggregated flow count")
    axes[0].set_ylabel("flows/sec")
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(loc="upper left")

    axes[1].plot([r["t"] for r in zr], [r["value"] for r in zr], label="flows/sec", color="#1f77b4", linewidth=1.6)
    axes[1].plot([r["t"] for r in zr], [r["rolling_avg"] for r in zr], label="rolling average", color="#ff7f0e", linewidth=1.4)
    axes[1].scatter([r["t"] for r in zr if r["label"]], [r["value"] for r in zr if r["label"]],
                    color="#d62728", s=16, label="attack label", zorder=4)
    axes[1].set_title("Zoom: rolling average follows the attack but decays slowly")
    axes[1].set_ylabel("flows/sec")
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(loc="upper left")

    axes[2].plot(t, avg_score, label="rolling average robust z-score", color="#ff7f0e", linewidth=1.1)
    axes[2].plot(t, db4_score, label="DB4 detail robust z-score", color="#2ca02c", linewidth=1.1)
    axes[2].axhline(4.0, color="#d62728", linestyle="--", linewidth=1.0, label="threshold z=4")
    axes[2].scatter(db4_alert_t, db4_alert_y, color="#d62728", s=10, label="DB4 alerts", zorder=4)
    axes[2].set_title("Robust z-scores: DB4 reacts to sharp transitions")
    axes[2].set_ylabel("z-score")
    axes[2].grid(True, alpha=0.25)
    axes[2].legend(loc="upper left")

    names = ["TP", "FP", "FN"]
    x = range(len(names))
    axes[3].bar([i - 0.18 for i in x], [avg_tp, avg_fp, avg_fn], width=0.36,
                label="rolling average z-score", color="#ff7f0e")
    axes[3].bar([i + 0.18 for i in x], [db4_tp, db4_fp, db4_fn], width=0.36,
                label="Daubechies D4 z-score", color="#2ca02c")
    axes[3].set_xticks(list(x))
    axes[3].set_xticklabels(names)
    axes[3].set_title("Event-level comparison on real Portmap.csv")
    axes[3].set_ylabel("events / seconds")
    axes[3].grid(True, axis="y", alpha=0.25)
    axes[3].legend(loc="upper right")

    fig.tight_layout()
    fig.savefig("portmap_real_db4.png", dpi=160)
    print("wrote portmap_real_db4.png")


if __name__ == "__main__":
    main()
