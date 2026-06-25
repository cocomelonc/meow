#!/usr/bin/env python3
import csv

import matplotlib.pyplot as plt


def read_csv(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "t": int(row["t"]),
                "traffic": float(row["traffic"]),
                "rolling_avg": float(row["rolling_avg"]),
                "haar_detail": float(row["haar_detail"]),
                "wavelet_score": float(row["wavelet_score"]),
                "avg_alert": int(row["avg_alert"]),
                "wavelet_alert": int(row["wavelet_alert"]),
                "is_attack": int(row["is_attack"]),
            })
    return rows


def main():
    rows = read_csv("wavelet_ddos.csv")

    t = [r["t"] for r in rows]
    traffic = [r["traffic"] for r in rows]
    rolling = [r["rolling_avg"] for r in rows]
    score = [r["wavelet_score"] for r in rows]
    attack_t = [r["t"] for r in rows if r["is_attack"]]
    attack_y = [r["traffic"] for r in rows if r["is_attack"]]
    wav_alert_t = [r["t"] for r in rows if r["wavelet_alert"]]
    wav_alert_y = [r["wavelet_score"] for r in rows if r["wavelet_alert"]]

    fig, axes = plt.subplots(2, 1, figsize=(12, 7), sharex=True)

    axes[0].plot(t, traffic, label="traffic rate", color="#1f77b4", linewidth=1.8)
    axes[0].plot(t, rolling, label="rolling average (16 samples)", color="#ff7f0e", linewidth=1.6)
    axes[0].axhline(30.0, color="#d62728", linestyle="--", linewidth=1.2, label="average threshold")
    axes[0].scatter(attack_t, attack_y, color="#d62728", s=28, label="attack samples", zorder=5)
    axes[0].set_ylabel("k packets/sec")
    axes[0].set_title("Short DDoS pulses: average hides the attack")
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(loc="upper right")

    axes[1].plot(t, score, label="Haar wavelet z-score", color="#2ca02c", linewidth=1.8)
    axes[1].axhline(8.0, color="#d62728", linestyle="--", linewidth=1.2, label="wavelet threshold")
    axes[1].scatter(wav_alert_t, wav_alert_y, color="#d62728", s=28, label="wavelet alerts", zorder=5)
    axes[1].set_xlabel("time sample")
    axes[1].set_ylabel("robust z-score")
    axes[1].set_title("Haar detail coefficients catch the sharp edges")
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(loc="upper right")

    fig.tight_layout()
    fig.savefig("wavelet_ddos.png", dpi=160)
    print("wrote wavelet_ddos.png")


if __name__ == "__main__":
    main()
