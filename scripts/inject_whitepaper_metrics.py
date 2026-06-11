import argparse
import csv
from pathlib import Path


def parse_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def load_rows(csv_path: Path):
    rows = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
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
                    "overhead_ratio": float(row["overhead_ratio"]),
                }
            )
    return rows


def format_percent(part: int, total: int) -> str:
    if total == 0:
        return "N/A"
    pct = (part / total) * 100.0
    return f"{part}/{total} ({pct:.1f}%)"


def is_success(row) -> bool:
    return row["initiator_ok"] and row["responder_ok"]


PROFILE_KEYS = {
    (10, 50, 0): "mobile_3g_edge",
    (20, 10, 10): "congested_wifi",
    (30, 20, 25): "starlink_storm",
    (5, 5, 5): "datacenter_flap",
}


def detect_allframes_profiles(rows):
    out = []
    for r in rows:
        key = (r["loss_pct"], r["jitter_ms"], r["reorder_pct"])
        if key in PROFILE_KEYS:
            out.append(r)
    return out


def profile_name(row):
    key = (row["loss_pct"], row["jitter_ms"], row["reorder_pct"])
    return PROFILE_KEYS.get(key, f"loss{key[0]}_jit{key[1]}_reord{key[2]}")


def main():
    parser = argparse.ArgumentParser(description="Inject benchmark metrics into WHITEPAPER placeholders")
    parser.add_argument("--csv", default="whitepaper_benchmarks.csv")
    parser.add_argument("--whitepaper", default="WHITEPAPER.md")
    parser.add_argument("--payload-bytes", type=int, default=262144)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    wp_path = Path(args.whitepaper)

    rows = load_rows(csv_path)
    if not rows:
        raise SystemExit("CSV has no rows")

    allframes_rows = detect_allframes_profiles(rows)
    dataonly_rows = [
        r
        for r in rows
        if (r["loss_pct"], r["jitter_ms"], r["reorder_pct"]) not in PROFILE_KEYS
    ]

    if not args.allow_partial:
        expected_profiles = set(PROFILE_KEYS.keys())
        seen_profiles = {
            (r["loss_pct"], r["jitter_ms"], r["reorder_pct"]) for r in allframes_rows
        }
        missing = expected_profiles - seen_profiles
        if len(dataonly_rows) < 54 or missing:
            raise SystemExit(
                "Benchmark dataset is incomplete; rerun full matrix before injection "
                f"(dataonly={len(dataonly_rows)}, allframes={len(allframes_rows)}, missing_profiles={sorted(missing)})"
            )

    if not dataonly_rows:
        raise SystemExit("No DataOnly rows found")

    min_overhead = min(r["overhead_ratio"] for r in dataonly_rows)
    max_overhead = max(r["overhead_ratio"] for r in dataonly_rows)

    dataonly_success = sum(1 for r in dataonly_rows if is_success(r))
    dataonly_total = len(dataonly_rows)

    allframes_success = sum(1 for r in allframes_rows if is_success(r))
    allframes_total = len(allframes_rows)

    starlink = None
    for r in allframes_rows:
        if profile_name(r) == "starlink_storm":
            starlink = r
            break

    starlink_success = "N/A"
    if starlink is not None:
        starlink_success = "true" if is_success(starlink) else "false"

    text = wp_path.read_text(encoding="utf-8")
    replacements = {
        "[INSERT_PAYLOAD_BYTES]": str(args.payload_bytes),
        "[INSERT_OVERHEAD_RANGE]": f"{min_overhead:.4f}-{max_overhead:.4f}",
        "[INSERT_DATAONLY_SUCCESS_RATE]": format_percent(dataonly_success, dataonly_total),
        "[INSERT_ALLFRAMES_CLOSE_SUCCESS_RATE]": format_percent(allframes_success, allframes_total),
        "[INSERT_STARLINK_STORM_CLOSE_SUCCESS]": starlink_success,
    }

    for key, value in replacements.items():
        text = text.replace(key, value)

    wp_path.write_text(text, encoding="utf-8")

    print("Injected placeholders:")
    for key, value in replacements.items():
        print(f"{key} -> {value}")


if __name__ == "__main__":
    main()
