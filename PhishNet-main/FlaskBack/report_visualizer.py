"""
PhishNet Performance Report Visualizer
========================================
Reads JSON output from performance_test.py and generates charts.

Usage:
    python report_visualizer.py --report reports/perf_report_YYYYMMDD_HHMMSS.json
    python report_visualizer.py --report reports/perf_report_*.json   # latest
"""

import json
import argparse
import glob
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[warn] matplotlib not installed. Run: pip install matplotlib numpy")
    print("       Charts will be skipped, text summary only.\n")


def load_report(path: str) -> list:
    with open(path) as f:
        return json.load(f)


def text_summary(data: list):
    print("\n" + "=" * 62)
    print("  PhishNet Performance Report — Summary")
    print("=" * 62)
    fmt = "  {:<32}  {:>8}  {:>8}  {:>8}  {:>6}"
    print(fmt.format("Test", "Avg(ms)", "P95(ms)", "RPS", "Err%"))
    print("  " + "-" * 58)
    for d in data:
        lat  = d["latency_ms"]
        err  = 100 - d["success_rate_pct"]
        print(fmt.format(
            d["test_name"][:32],
            f"{lat['avg']:.0f}",
            f"{lat['p95']:.0f}",
            f"{d['rps']:.2f}",
            f"{err:.1f}%",
        ))
    print("=" * 62)


def plot_latency_comparison(data: list, out_dir: str):
    """Bar chart: avg / p95 / p99 per test."""
    names = [d["test_name"] for d in data]
    avgs  = [d["latency_ms"]["avg"]  for d in data]
    p95s  = [d["latency_ms"]["p95"]  for d in data]
    p99s  = [d["latency_ms"]["p99"]  for d in data]

    x   = np.arange(len(names))
    w   = 0.26
    fig, ax = plt.subplots(figsize=(14, 6))

    ax.bar(x - w,   avgs, w, label="Avg",  color="#4e79a7")
    ax.bar(x,       p95s, w, label="P95",  color="#f28e2b")
    ax.bar(x + w,   p99s, w, label="P99",  color="#e15759")

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("PhishNet — Latency Comparison by Test Suite")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()
    path = os.path.join(out_dir, "latency_comparison.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  Chart saved → {path}")


def plot_throughput(data: list, out_dir: str):
    """Horizontal bar: requests/sec per test."""
    names = [d["test_name"] for d in data]
    rps   = [d["rps"] for d in data]
    colors = ["#76b7b2" if r > 0.5 else "#e15759" for r in rps]

    fig, ax = plt.subplots(figsize=(10, max(4, len(names) * 0.6)))
    bars = ax.barh(names, rps, color=colors)
    ax.bar_label(bars, fmt="%.2f req/s", padding=4, fontsize=8)
    ax.set_xlabel("Requests per Second")
    ax.set_title("PhishNet — Throughput (req/s) per Test Suite")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    plt.tight_layout()
    path = os.path.join(out_dir, "throughput.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  Chart saved → {path}")


def plot_success_rate(data: list, out_dir: str):
    """Donut-style per test showing success vs failure."""
    n   = len(data)
    cols = min(3, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 4, rows * 4))
    axes = np.array(axes).flatten() if n > 1 else [axes]

    for i, (d, ax) in enumerate(zip(data, axes)):
        ok  = d["success_rate_pct"]
        err = 100 - ok
        wedge_colors = ["#76b7b2", "#e15759"] if err > 0 else ["#76b7b2"]
        sizes  = [ok, err] if err > 0 else [ok]
        labels = [f"OK {ok:.1f}%", f"Err {err:.1f}%"] if err > 0 else [f"OK {ok:.1f}%"]
        ax.pie(sizes, labels=labels, colors=wedge_colors,
               startangle=90, wedgeprops={"width": 0.55})
        ax.set_title(d["test_name"][:30], fontsize=9)

    for j in range(i + 1, len(axes)):
        axes[j].set_visible(False)

    fig.suptitle("PhishNet — Success Rate per Test Suite", fontsize=12)
    plt.tight_layout()
    path = os.path.join(out_dir, "success_rates.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  Chart saved → {path}")


def plot_latency_percentiles(data: list, out_dir: str):
    """Line chart showing min / avg / p50 / p95 / p99 / max trend."""
    names = [d["test_name"] for d in data]
    keys  = ["min", "avg", "p50", "p95", "p99", "max"]
    colors = ["#bab0ac", "#4e79a7", "#76b7b2", "#f28e2b", "#e15759", "#b07aa1"]

    x   = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(14, 6))

    for key, color in zip(keys, colors):
        vals = [d["latency_ms"].get(key, 0) for d in data]
        ax.plot(x, vals, marker="o", label=key.upper(), color=color, linewidth=1.8)

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("PhishNet — Latency Percentile Trends")
    ax.legend(ncol=3, fontsize=8)
    ax.grid(linestyle="--", alpha=0.3)
    plt.tight_layout()
    path = os.path.join(out_dir, "latency_percentiles.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  Chart saved → {path}")


def main():
    parser = argparse.ArgumentParser(description="PhishNet Perf Report Visualizer")
    parser.add_argument("--report", required=True, help="Path to JSON report (glob ok)")
    parser.add_argument("--out",    default="reports/charts", help="Output directory for charts")
    args = parser.parse_args()

    # Resolve glob
    paths = sorted(glob.glob(args.report))
    if not paths:
        print(f"No report found at: {args.report}")
        sys.exit(1)
    path = paths[-1]  # latest
    print(f"\nLoading report: {path}")

    data = load_report(path)
    os.makedirs(args.out, exist_ok=True)

    text_summary(data)

    if HAS_MPL and data:
        print("\nGenerating charts...")
        plot_latency_comparison(data, args.out)
        plot_throughput(data, args.out)
        plot_success_rate(data, args.out)
        plot_latency_percentiles(data, args.out)
        print(f"\nAll charts saved in: {args.out}/")
    elif not HAS_MPL:
        print("\nInstall matplotlib to generate charts:  pip install matplotlib numpy")


if __name__ == "__main__":
    main()
