import argparse
import csv
import os
from collections import defaultdict

import matplotlib.pyplot as plt


def parse_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def load_rows(csv_path: str):
    rows = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(
                {
                    "run_id": int(row["run_id"]),
                    "loss_pct": int(row["loss_pct"]),
                    "jitter_ms": int(row["jitter_ms"]),
                    "reorder_pct": int(row["reorder_pct"]),
                    "initiator_ok": parse_bool(row["initiator_ok"]),
                    "responder_ok": parse_bool(row["responder_ok"]),
                    "end_to_end_ms": float(row["end_to_end_ms"]),
                    "recovery_time_ms": float(row["recovery_time_ms"]),
                    "goodput_bytes_per_sec": float(row["goodput_bytes_per_sec"]),
                    "overhead_ratio": float(row["overhead_ratio"]),
                }
            )
    return rows


def split_dataonly_and_profiles(rows):
    # Orchestrator appends 4 named AllFrames profiles after the DataOnly matrix.
    if len(rows) >= 4:
        return rows[:-4], rows[-4:]
    return rows, []


def build_survivability_curve(data_rows):
    grouped = defaultdict(list)
    for r in data_rows:
        grouped[r["loss_pct"]].append(r["goodput_bytes_per_sec"])

    losses = sorted(grouped.keys())
    mbps = [sum(grouped[l]) / len(grouped[l]) / (1024 * 1024) for l in losses]
    return losses, mbps


def profile_name(row):
    key = (row["loss_pct"], row["jitter_ms"], row["reorder_pct"])
    names = {
        (10, 50, 0): "mobile_3g_edge",
        (20, 10, 10): "congested_wifi",
        (30, 20, 25): "starlink_storm",
        (5, 5, 5): "datacenter_flap",
    }
    return names.get(key, f"loss{key[0]}_jit{key[1]}_reord{key[2]}")


def plot_survivability_curve(losses, mbps, output_path):
    plt.figure(figsize=(10, 5))
    plt.plot(losses, mbps, marker="o", linewidth=2)
    plt.title("Velyx Survivability Curve (DataOnly)")
    plt.xlabel("Loss (%)")
    plt.ylabel("Average Goodput (MiB/s)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def plot_allframes_stress(profile_rows, output_path):
    if not profile_rows:
        return

    names = [profile_name(r) for r in profile_rows]
    recovery = [r["recovery_time_ms"] for r in profile_rows]
    ok_flags = [r["initiator_ok"] and r["responder_ok"] for r in profile_rows]

    colors = ["#2e7d32" if ok else "#c62828" for ok in ok_flags]

    fig, ax1 = plt.subplots(figsize=(11, 6))
    bars = ax1.bar(names, recovery, color=colors, alpha=0.85)
    ax1.set_title("AllFrames Stress Profiles")
    ax1.set_xlabel("Profile")
    ax1.set_ylabel("Recovery Time (ms)")
    ax1.tick_params(axis="x", rotation=15)

    for bar, ok in zip(bars, ok_flags):
        text = "OK" if ok else "FAIL"
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            text,
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold",
        )

    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot Velyx benchmark charts from CSV")
    parser.add_argument("--input", default="whitepaper_benchmarks.csv", help="Input CSV path")
    parser.add_argument("--outdir", default="charts", help="Output directory for PNG charts")
    args = parser.parse_args()

    rows = load_rows(args.input)
    if not rows:
        raise SystemExit("No rows found in CSV")

    os.makedirs(args.outdir, exist_ok=True)

    data_rows, profile_rows = split_dataonly_and_profiles(rows)
    losses, mbps = build_survivability_curve(data_rows)

    surv_path = os.path.join(args.outdir, "survivability_curve.png")
    allf_path = os.path.join(args.outdir, "allframes_stress.png")

    plot_survivability_curve(losses, mbps, surv_path)
    plot_allframes_stress(profile_rows, allf_path)

    print(f"Wrote: {surv_path}")
    if profile_rows:
        print(f"Wrote: {allf_path}")
    else:
        print("Skipped AllFrames chart (need at least 4 profile rows)")


if __name__ == "__main__":
    main()
