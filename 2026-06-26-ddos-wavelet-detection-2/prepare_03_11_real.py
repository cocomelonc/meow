#!/usr/bin/env python3
# author @cocomelonc
import argparse
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path


TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
]


def clean_name(name):
    return name.strip().lower().replace(" ", "").replace("_", "")


def find_column(fieldnames, wanted):
    normalized = {clean_name(name): name for name in fieldnames}
    for name in wanted:
        key = clean_name(name)
        if key in normalized:
            return normalized[key]
    raise SystemExit(f"column not found: {wanted}")


def parse_timestamp(value):
    value = value.strip()
    if "." in value:
        head = value.split(".", 1)[0]
    else:
        head = value

    for fmt in TIMESTAMP_FORMATS:
        try:
            return int(datetime.strptime(head, fmt).timestamp())
        except ValueError:
            pass

    raise ValueError(f"unsupported timestamp: {value!r}")


def main():
    parser = argparse.ArgumentParser(
        description="Prepare a real CICDDoS2019 03-11 CSV as t,value,label time series."
    )
    parser.add_argument("--input", default="03-11/Portmap.csv")
    parser.add_argument("-o", "--output", default="portmap_real_timeseries.csv")
    parser.add_argument("--attack-label", default="Portmap")
    parser.add_argument(
        "--feature",
        default="count",
        help="'count' for flows/sec or any numeric CICFlowMeter column, e.g. 'Total Fwd Packets'.",
    )
    args = parser.parse_args()

    src = Path(args.input)
    buckets = defaultdict(float)
    labels = defaultdict(int)
    rows = 0
    start_ts = None

    with src.open(newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("empty CSV")

        ts_col = find_column(reader.fieldnames, ["Timestamp"])
        label_col = find_column(reader.fieldnames, ["Label"])
        feature_col = None
        if args.feature.lower() != "count":
            feature_col = find_column(reader.fieldnames, [args.feature])

        for row in reader:
            try:
                ts = parse_timestamp(row[ts_col])
            except Exception:
                continue

            if start_ts is None:
                start_ts = ts
            t = ts - start_ts

            label = row[label_col].strip()
            is_attack = int(label.lower() == args.attack_label.lower())

            if args.feature.lower() == "count":
                value = 1.0
            else:
                try:
                    value = float(row[feature_col])
                except Exception:
                    value = 0.0

            buckets[t] += value
            labels[t] = max(labels[t], is_attack)
            rows += 1

    if not buckets:
        raise SystemExit("no rows converted")

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t", "value", "label"])
        for t in range(max(buckets) + 1):
            writer.writerow([t, f"{buckets.get(t, 0.0):.8f}", labels.get(t, 0)])

    attack_seconds = sum(labels.values())
    print(f"source: {src}")
    print(f"rows converted: {rows}")
    print(f"seconds: {max(buckets) + 1}")
    print(f"attack-labeled seconds: {attack_seconds}")
    print(f"feature: {args.feature}")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
