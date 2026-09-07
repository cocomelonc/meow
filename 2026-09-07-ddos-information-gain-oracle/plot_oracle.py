#!/usr/bin/env python3
"""Plot the pooled question-budget/quality trade-off and per-file errors
from oracle-results.json (produced by oracle.py)."""
import json
from collections import defaultdict

import matplotlib.pyplot as plt


def load(path):
    with open(path) as f:
        return json.load(f)


def pooled_by_depth(results):
    agg = defaultdict(lambda: dict(tn=0, fp=0, fn=0, tp=0, q_sum=0.0, n=0))
    for r in results:
        d = agg[r["depth"]]
        for k in ("tn", "fp", "fn", "tp"):
            d[k] += r[k]
        n = r["tn"] + r["fp"] + r["fn"] + r["tp"]
        d["q_sum"] += r["mean_questions"] * n
        d["n"] += n
    rows = []
    for depth, d in sorted(agg.items()):
        fpr = d["fp"] / (d["fp"] + d["tn"])
        recall = d["tp"] / (d["tp"] + d["fn"])
        mean_q = d["q_sum"] / d["n"]
        rows.append((depth, mean_q, fpr, recall))
    return rows


def plot_tradeoff(rows, out):
    depths = [r[0] for r in rows]
    mean_q = [r[1] for r in rows]
    fpr = [r[2] * 100 for r in rows]
    recall = [r[3] * 100 for r in rows]

    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax1.plot(mean_q, fpr, "o-", color="#d62728", linewidth=1.8, label="FPR")
    ax1.set_xlabel("mean questions asked per flow")
    ax1.set_ylabel("FPR, %", color="#d62728")
    ax1.tick_params(axis="y", labelcolor="#d62728")
    for x, y, d in zip(mean_q, fpr, depths):
        ax1.annotate(f"depth {d}", (x, y), textcoords="offset points", xytext=(8, 8))

    ax2 = ax1.twinx()
    ax2.plot(mean_q, recall, "s-", color="#2ca02c", linewidth=1.8, label="Recall")
    ax2.set_ylabel("Recall, %", color="#2ca02c")
    ax2.tick_params(axis="y", labelcolor="#2ca02c")
    ax2.set_ylim(99.5, 100.05)

    ax1.set_title("Question budget vs. detection quality (pooled, 7 folds)")
    ax1.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(out, dpi=160)
    print(f"wrote {out}")


def plot_per_file(results, out, depth=4):
    rows = [r for r in results if r["depth"] == depth]
    rows.sort(key=lambda r: r["file"])
    files = [r["file"] for r in rows]
    fp = [r["fp"] for r in rows]
    fn = [r["fn"] for r in rows]

    x = range(len(files))
    width = 0.35
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width / 2 for i in x], fp, width,
           label="false positives (benign flagged as attack)", color="#d62728")
    ax.bar([i + width / 2 for i in x], fn, width,
           label="missed attacks", color="#1f77b4")
    ax.set_xticks(list(x))
    ax.set_xticklabels(files, rotation=30, ha="right")
    ax.set_ylabel("flows")
    ax.set_title(f"Per-file errors at depth {depth} (held-out fold)")
    ax.legend()
    ax.grid(True, alpha=0.25, axis="y")
    fig.tight_layout()
    fig.savefig(out, dpi=160)
    print(f"wrote {out}")


def main():
    data = load("oracle-results.json")
    rows = pooled_by_depth(data["results"])
    for depth, mean_q, fpr, recall in rows:
        print(f"depth={depth} mean_questions={mean_q:.2f} fpr={fpr:.4f} recall={recall:.5f}")
    plot_tradeoff(rows, "oracle_depth_tradeoff.png")
    plot_per_file(data["results"], "oracle_per_file_depth4.png")


if __name__ == "__main__":
    main()
