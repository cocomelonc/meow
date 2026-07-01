#!/usr/bin/env python3
# author @cocomelonc
import re
import subprocess

import matplotlib.pyplot as plt

THRESHOLDS = [2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 30, 40, 60, 80, 100]

def run_detector(th):
    out = subprocess.check_output([
        "./hack",
        "syn_handshake_timeseries.csv",
        "syn_scan_results.csv",
        str(th),
        str(th),
    ], text=True)

    pattern = re.compile(r"TP=(\d+) FP=(\d+) FN=(\d+) events=(\d+)")
    rows = pattern.findall(out)
    if len(rows) != 2:
        raise RuntimeError(out)
    volume = tuple(map(int, rows[0]))
    asym = tuple(map(int, rows[1]))
    return volume, asym


def main():
    volume_tp = []
    volume_fp = []
    volume_fn = []
    asym_tp = []
    asym_fp = []
    asym_fn = []

    for th in THRESHOLDS:
        volume, asym = run_detector(th)
        volume_tp.append(volume[0])
        volume_fp.append(volume[1])
        volume_fn.append(volume[2])
        asym_tp.append(asym[0])
        asym_fp.append(asym[1])
        asym_fn.append(asym[2])

    fig, axes = plt.subplots(2, 1, figsize=(11, 8), sharex=True)

    axes[0].plot(THRESHOLDS, volume_tp, marker="o", label="volume TP", color="#ff7f0e")
    axes[0].plot(THRESHOLDS, asym_tp, marker="o", label="asymmetry TP", color="#2ca02c")
    axes[0].plot(THRESHOLDS, volume_fn, marker="x", linestyle="--", label="volume FN", color="#ffbb78")
    axes[0].plot(THRESHOLDS, asym_fn, marker="x", linestyle="--", label="asymmetry FN", color="#98df8a")
    axes[0].set_ylabel("campaigns")
    axes[0].set_title("SYN campaign detection vs threshold")
    axes[0].grid(True, alpha=0.25)
    axes[0].legend(loc="best")

    axes[1].plot(THRESHOLDS, volume_fp, marker="o", label="volume FP", color="#ff7f0e")
    axes[1].plot(THRESHOLDS, asym_fp, marker="o", label="asymmetry FP", color="#2ca02c")
    axes[1].set_xlabel("robust z-score threshold")
    axes[1].set_ylabel("false positives")
    axes[1].set_title("False positives stay zero at campaign level in this scan")
    axes[1].grid(True, alpha=0.25)
    axes[1].legend(loc="best")

    fig.tight_layout()
    fig.savefig("syn_threshold_scan.png", dpi=160)
    print("wrote syn_threshold_scan.png")


if __name__ == "__main__":
    main()
