#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict
from datetime import datetime


TIMESTAMP_FORMATS = [
    "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
]


def clean_name(name):
    return name.strip().lower().replace(" ", "").replace("_", "")


def find_column(fieldnames, candidates):
    normalized = {clean_name(name): name for name in fieldnames}
    for candidate in candidates:
        key = clean_name(candidate)
        if key in normalized:
            return normalized[key]
    return None


def parse_timestamp(value):
    value = value.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return int(datetime.strptime(value, fmt).timestamp())
        except ValueError:
            pass

    # Some CICFlowMeter exports include fractional seconds.
    if "." in value:
        head = value.split(".", 1)[0]
        for fmt in TIMESTAMP_FORMATS:
            try:
                return int(datetime.strptime(head, fmt).timestamp())
            except ValueError:
                pass

    raise ValueError(f"unsupported timestamp: {value!r}")


def is_attack_label(label, attack_filter):
    label_norm = label.strip().lower()
    if label_norm == "benign":
        return False
    if attack_filter is None:
        return True
    return attack_filter.lower() in label_norm


def main():
    parser = argparse.ArgumentParser(
        description="Convert CICDDoS2019 CICFlowMeter CSV to t,value,label time series."
    )
    parser.add_argument("input", help="CICDDoS2019 flow CSV")
    parser.add_argument("-o", "--output", default="cic_timeseries.csv")
    parser.add_argument(
        "--value-column",
        default=None,
        help="Numeric column to aggregate. Default: Total Fwd Packets or Flow Packets/s.",
    )
    parser.add_argument(
        "--attack-filter",
        default=None,
        help="Optional substring filter, for example SYN, UDP, DNS, LDAP.",
    )
    parser.add_argument(
        "--mode",
        choices=["sum", "count"],
        default="sum",
        help="sum selected value column or count flows per second.",
    )
    args = parser.parse_args()

    buckets = defaultdict(float)
    labels = defaultdict(int)

    with open(args.input, newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("empty CSV")

        timestamp_col = find_column(reader.fieldnames, ["Timestamp", "Flow ID Timestamp"])
        label_col = find_column(reader.fieldnames, ["Label"])

        if args.value_column:
            value_col = find_column(reader.fieldnames, [args.value_column])
        else:
            value_col = find_column(reader.fieldnames, [
                "Total Fwd Packets",
                "Tot Fwd Pkts",
                "Flow Packets/s",
                "Flow Pkts/s",
            ])

        if not timestamp_col:
            raise SystemExit("Timestamp column not found")
        if not label_col:
            raise SystemExit("Label column not found")
        if args.mode == "sum" and not value_col:
            raise SystemExit("value column not found; use --mode count or --value-column")

        start_ts = None
        rows = 0
        for row in reader:
            try:
                ts = parse_timestamp(row[timestamp_col])
            except Exception:
                continue

            if start_ts is None:
                start_ts = ts
            t = ts - start_ts

            attack = is_attack_label(row[label_col], args.attack_filter)
            if args.mode == "count":
                value = 1.0
            else:
                try:
                    value = float(row[value_col])
                except Exception:
                    value = 0.0

            buckets[t] += value
            labels[t] = max(labels[t], int(attack))
            rows += 1

    if not buckets:
        raise SystemExit("no rows converted")

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["t", "value", "label"])

        last_t = max(buckets)
        for t in range(last_t + 1):
            writer.writerow([t, f"{buckets.get(t, 0.0):.8f}", labels.get(t, 0)])

    print(f"converted rows: {rows}")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
