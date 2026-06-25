#!/usr/bin/env python3
# author @cocomelonc
import csv
import math


def is_attack(t):
    return 170 <= t <= 176 or 260 <= t <= 268

def value_at(t):
    baseline = 120.0 + 16.0 * math.sin(2.0 * math.pi * t / 96.0)
    tiny_noise = ((t * 17) % 13) * 0.9

    # CICDDoS-like flow aggregation: mostly calm baseline, then short
    # high-rate attack intervals.
    if 170 <= t <= 176:
        return 1450.0 + ((t * 19) % 31) * 4.0
    if 260 <= t <= 268:
        return 1120.0 + ((t * 23) % 29) * 3.5

    return baseline + tiny_noise

def main():
    with open("fixture_cic_timeseries.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t", "value", "label"])
        for t in range(360):
            writer.writerow([t, f"{value_at(t):.6f}", int(is_attack(t))])

    print("wrote fixture_cic_timeseries.csv")

if __name__ == "__main__":
    main()
