"""
WOT cross-rev overlay plotter (SOP step 2.7.7).

Reads trends/wot_shortlist.csv and trends/wot_trajectories.csv, overlays
same-gear pulls across revs as mrp/target, wgdc, and Tdp vs RPM.

Pulls are grouped by their FIRST detected gear segment (gear_ratios col,
first value). For each gear bucket present in >=2 revs, emits one PNG.

Usage:
    python wot_overlay_plot.py                # all gears with >=2 revs
    python wot_overlay_plot.py --gear 102.8   # one specific gear bucket
    python wot_overlay_plot.py --bin 5        # gear-bucket width (default 5)
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"
PLOTS_DIR = REPO_ROOT / "scripts" / "analysis" / "plots"
DEFAULT_BIN = 5.0  # gear-ratio bucket width


def _first_gear(s):
    if not isinstance(s, str) or not s.strip():
        return float("nan")
    parts = s.split(",")
    try:
        return float(parts[0])
    except ValueError:
        return float("nan")


def _bucket(ratio, bin_w):
    if not np.isfinite(ratio):
        return float("nan")
    return round(ratio / bin_w) * bin_w


def overlay(gear_filter=None, bin_w=DEFAULT_BIN, out_dir=None):
    out_dir = Path(out_dir) if out_dir else PLOTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    sl_path = TRENDS_DIR / "wot_shortlist.csv"
    tj_path = TRENDS_DIR / "wot_trajectories.csv"
    if not sl_path.exists() or not tj_path.exists():
        print(f"missing CSVs (need {sl_path} and {tj_path})", file=sys.stderr)
        return []
    sl = pd.read_csv(sl_path)
    tj = pd.read_csv(tj_path)
    if sl.empty or tj.empty:
        print("empty CSVs", file=sys.stderr)
        return []

    sl["first_gear"] = sl["gear_ratios"].apply(_first_gear)
    sl["gear_bucket"] = sl["first_gear"].apply(lambda r: _bucket(r, bin_w))

    if gear_filter is not None:
        sl = sl[sl["gear_bucket"] == _bucket(gear_filter, bin_w)]
        if sl.empty:
            print(f"no pulls in gear bucket {gear_filter}", file=sys.stderr)
            return []

    # Only plot buckets with >=2 distinct revs
    keep_buckets = []
    for bucket, group in sl.groupby("gear_bucket"):
        if not np.isfinite(bucket):
            continue
        if group["rom_rev"].nunique() >= 2:
            keep_buckets.append(bucket)
    if not keep_buckets and gear_filter is not None:
        # If user explicitly asked for a single gear, render even with 1 rev
        keep_buckets = list(sl["gear_bucket"].dropna().unique())

    # Lazy matplotlib import
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    paths = []
    for bucket in keep_buckets:
        bucket_pulls = sl[sl["gear_bucket"] == bucket]
        fig, (ax_mrp, ax_wgdc, ax_tdp) = plt.subplots(
            3, 1, figsize=(11, 9), sharex=True
        )
        ax_mrp.set_title(
            f"WOT overlay - gear ratio bucket {bucket:.0f} (+/-{bin_w/2:.0f}) "
            f"- {len(bucket_pulls)} pull(s), {bucket_pulls['rom_rev'].nunique()} rev(s)"
        )

        for _, row in bucket_pulls.iterrows():
            pid = row["pull_id"]
            sub = tj[tj["pull_id"] == pid].sort_values("sample_offset")
            if sub.empty:
                continue
            label = f"{row['rom_rev']} {pid.split('__', 1)[-1]}"
            ax_mrp.plot(sub["RPM"], sub["mrp"], label=label, linewidth=1.3)
            ax_mrp.plot(sub["RPM"], sub["Trgt_Boost"], linestyle="--",
                        linewidth=0.8, alpha=0.6)
            ax_wgdc.plot(sub["RPM"], sub["wgdc"], label=label, linewidth=1.3)
            ax_tdp.plot(sub["RPM"], sub["Tdp"], label=label, linewidth=1.3)

        ax_mrp.set_ylabel("mrp / target (psi)")
        ax_mrp.grid(True, alpha=0.3)
        ax_mrp.legend(fontsize=7, loc="lower right")
        ax_wgdc.set_ylabel("wgdc (%)")
        ax_wgdc.grid(True, alpha=0.3)
        ax_tdp.set_ylabel("Tdp (%)")
        ax_tdp.set_xlabel("RPM")
        ax_tdp.grid(True, alpha=0.3)
        ax_tdp.axhline(0, color="k", linewidth=0.5, alpha=0.5)

        out_path = out_dir / f"wot_overlay__gear{int(bucket)}.png"
        fig.tight_layout()
        fig.savefig(out_path, dpi=110)
        plt.close(fig)
        paths.append(out_path)
        print(f"wrote {out_path}")
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gear", type=float, default=None,
                    help="Filter to a specific gear ratio (rounded to --bin)")
    ap.add_argument("--bin", type=float, default=DEFAULT_BIN,
                    help=f"Gear-ratio bucket width (default {DEFAULT_BIN})")
    ap.add_argument("--out", type=str, default=None,
                    help="Output dir (default scripts/analysis/plots/)")
    args = ap.parse_args()
    overlay(gear_filter=args.gear, bin_w=args.bin, out_dir=args.out)


if __name__ == "__main__":
    main()
