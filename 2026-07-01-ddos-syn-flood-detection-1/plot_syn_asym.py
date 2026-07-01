#!/usr/bin/env python3
# author @cocomelonc
import csv

import matplotlib.pyplot as plt


EVENT_MERGE_GAP = 60
EVENT_GRACE = 3


def read_csv(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "t": int(row["t"]),
                "flows": float(row["flows"]),
                "fwd_pkts": float(row["fwd_pkts"]),
                "bwd_pkts": float(row["bwd_pkts"]),
                "oneway_flows": float(row["oneway_flows"]),
                "label": int(row["label"]),
                "one_way_ratio": float(row["one_way_ratio"]),
                "fb_ratio": float(row["fb_ratio"]),
                "volume_z": float(row["volume_z"]),
                "asym_z": float(row["asym_z"]),
                "volume_alert": int(row["volume_alert"]),
                "asym_alert": int(row["asym_alert"]),
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


def best_zoom(rows, width=260):
    labels = [r["label"] for r in rows]
    best_i = 0
    best_score = -1
    for i in range(0, max(1, len(rows) - width)):
        score = sum(labels[i:i + width]) + 0.001 * max(r["flows"] for r in rows[i:i + width])
        if score > best_score:
            best_score = score
            best_i = i
    return best_i, min(len(rows), best_i + width)


def main():
    rows = read_csv("syn_asym_results.csv")

    t = [r["t"] for r in rows]
    flows = [r["flows"] for r in rows]
    volume_z = [r["volume_z"] for r in rows]
    asym_z = [r["asym_z"] for r in rows]
    one_way_ratio = [r["one_way_ratio"] for r in rows]
    fb_ratio = [min(r["fb_ratio"], 200.0) for r in rows]

    attack_t = [r["t"] for r in rows if r["label"]]
    attack_y = [r["flows"] for r in rows if r["label"]]
    asym_alert_t = [r["t"] for r in rows if r["asym_alert"]]
    asym_alert_y = [r["asym_z"] for r in rows if r["asym_alert"]]

    volume_tp, volume_fp, volume_fn, _ = event_metrics(rows, "volume_alert")
    asym_tp, asym_fp, asym_fn, _ = event_metrics(rows, "asym_alert")

    zs, ze = best_zoom(rows)
    zr = rows[zs:ze]

    fig, axes = plt.subplots(5, 1, figsize=(14, 15))

    axes[0].plot(t, flows, label="TCP flows/sec", color="#1f77b4", linewidth=1.1)
    axes[0].scatter(attack_t, attack_y, s=6, color="#d62728", label="Syn label", zorder=4)
    axes[0].set_title("CICDDoS2019 03-11 Syn.csv: TCP flow count")
    axes[0].set_ylabel("flows/sec")
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(loc="upper right")

    axes[1].plot([r["t"] for r in zr], [r["flows"] for r in zr],
                 label="flows/sec", color="#1f77b4", linewidth=1.5)
    axes[1].plot([r["t"] for r in zr], [r["fwd_pkts"] for r in zr],
                 label="forward packets/sec", color="#9467bd", linewidth=1.2)
    axes[1].plot([r["t"] for r in zr], [r["bwd_pkts"] for r in zr],
                 label="backward packets/sec", color="#8c564b", linewidth=1.2)
    axes[1].scatter([r["t"] for r in zr if r["label"]], [r["flows"] for r in zr if r["label"]],
                    color="#d62728", s=14, label="attack label", zorder=4)
    axes[1].set_title("Zoom: forward/backward packet asymmetry during SYN flood")
    axes[1].set_ylabel("count/sec")
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(loc="upper right")

    axes[2].plot(t, one_way_ratio, label="one-way flow ratio", color="#2ca02c", linewidth=1.0)
    axes[2].plot(t, fb_ratio, label="fwd/bwd packet ratio (clipped at 200)", color="#ff7f0e", linewidth=1.0)
    axes[2].set_title("Handshake asymmetry components")
    axes[2].set_ylabel("ratio")
    axes[2].grid(True, alpha=0.25)
    axes[2].legend(loc="upper right")

    axes[3].plot(t, volume_z, label="volume z-score", color="#ff7f0e", linewidth=1.0)
    axes[3].plot(t, asym_z, label="handshake asymmetry z-score", color="#2ca02c", linewidth=1.0)
    axes[3].axhline(8.0, color="#d62728", linestyle="--", linewidth=1.0, label="threshold z=8")
    axes[3].scatter(asym_alert_t, asym_alert_y, s=8, color="#d62728", label="asym alerts", zorder=4)
    axes[3].set_title("Robust z-scores: asymmetry finds more SYN campaigns at the same FP")
    axes[3].set_ylabel("z-score")
    axes[3].grid(True, alpha=0.25)
    axes[3].legend(loc="upper right")

    names = ["TP", "FP", "FN"]
    x = range(len(names))
    axes[4].bar([i - 0.18 for i in x], [volume_tp, volume_fp, volume_fn], width=0.36,
                label="volume detector", color="#ff7f0e")
    axes[4].bar([i + 0.18 for i in x], [asym_tp, asym_fp, asym_fn], width=0.36,
                label="handshake asymmetry", color="#2ca02c")
    axes[4].set_xticks(list(x))
    axes[4].set_xticklabels(names)
    axes[4].set_title("Campaign-level comparison on real Syn.csv")
    axes[4].set_ylabel("campaigns")
    axes[4].grid(True, axis="y", alpha=0.25)
    axes[4].legend(loc="upper right")

    fig.tight_layout()
    fig.savefig("syn_asym_detection.png", dpi=160)
    print("wrote syn_asym_detection.png")


if __name__ == "__main__":
    main()
