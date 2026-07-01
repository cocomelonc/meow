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


def clean(name):
    return name.strip().lower().replace(" ", "").replace("_", "")


def find_col(fieldnames, candidates):
    table = {clean(c): c for c in fieldnames}
    for c in candidates:
        key = clean(c)
        if key in table:
            return table[key]
    raise SystemExit(f"column not found: {candidates}")


def parse_ts(value):
    value = value.strip()
    head = value.split(".", 1)[0]
    for fmt in TIMESTAMP_FORMATS:
        try:
            return int(datetime.strptime(head, fmt).timestamp())
        except ValueError:
            pass
    raise ValueError(f"unsupported timestamp: {value!r}")


def as_float(row, col):
    try:
        return float(row[col])
    except Exception:
        return 0.0


def main():
    parser = argparse.ArgumentParser(description="Prepare CICDDoS2019 Syn.csv for handshake-asymmetry detection.")
    parser.add_argument("--input", default="../blog_db4_ddos/03-11/Syn.csv")
    parser.add_argument("-o", "--output", default="syn_handshake_timeseries.csv")
    parser.add_argument("--attack-label", default="Syn")
    args = parser.parse_args()

    src = Path(args.input)
    buckets = defaultdict(lambda: {
        "flows": 0.0,
        "fwd_pkts": 0.0,
        "bwd_pkts": 0.0,
        "syn_flags": 0.0,
        "ack_flags": 0.0,
        "oneway": 0.0,
        "label": 0,
    })

    rows = 0
    start_ts = None

    with src.open(newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("empty CSV")

        ts_col = find_col(reader.fieldnames, ["Timestamp"])
        fwd_col = find_col(reader.fieldnames, ["Total Fwd Packets", "Tot Fwd Pkts"])
        bwd_col = find_col(reader.fieldnames, ["Total Backward Packets", "Tot Bwd Pkts"])
        syn_col = find_col(reader.fieldnames, ["SYN Flag Count"])
        ack_col = find_col(reader.fieldnames, ["ACK Flag Count"])
        proto_col = find_col(reader.fieldnames, ["Protocol"])
        label_col = find_col(reader.fieldnames, ["Label"])

        for row in reader:
            try:
                ts = parse_ts(row[ts_col])
            except Exception:
                continue

            if start_ts is None:
                start_ts = ts
            t = ts - start_ts

            proto = int(as_float(row, proto_col))
            if proto != 6:
                continue

            fwd = as_float(row, fwd_col)
            bwd = as_float(row, bwd_col)
            syn = as_float(row, syn_col)
            ack = as_float(row, ack_col)
            label = row[label_col].strip()

            b = buckets[t]
            b["flows"] += 1.0
            b["fwd_pkts"] += fwd
            b["bwd_pkts"] += bwd
            b["syn_flags"] += syn
            b["ack_flags"] += ack
            if bwd <= 0.0:
                b["oneway"] += 1.0
            if label.lower() == args.attack_label.lower():
                b["label"] = 1
            rows += 1

    if not buckets:
        raise SystemExit("no TCP rows converted")

    last_t = max(buckets)
    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "t",
            "flows",
            "fwd_pkts",
            "bwd_pkts",
            "syn_flags",
            "ack_flags",
            "oneway_flows",
            "label",
        ])
        for t in range(last_t + 1):
            b = buckets[t]
            writer.writerow([
                t,
                f"{b['flows']:.8f}",
                f"{b['fwd_pkts']:.8f}",
                f"{b['bwd_pkts']:.8f}",
                f"{b['syn_flags']:.8f}",
                f"{b['ack_flags']:.8f}",
                f"{b['oneway']:.8f}",
                b["label"],
            ])

    print(f"source: {src}")
    print(f"tcp rows converted: {rows}")
    print(f"seconds: {last_t + 1}")
    print(f"attack-labeled seconds: {sum(1 for v in buckets.values() if v['label'])}")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
