#!/usr/bin/env python3
"""
Cross-rev cell residency aggregator.

Reads every log in logs/rom_rev_map.csv, computes per-cell residency on the
AVCS Cruise table's RPM × load grid (the canonical cruise grid for this car),
emits scripts/analysis/trends/cell_residency.csv.

Used by the residency-threshold rule (SOP Step 4.2.1): cells with <1% strict-
cruise residency in the aggregated sample are "theater" — no log will ever
verify or refute a change there.

Aggregates across ALL rev-mapped logs by default. Residency is mostly
driver-pattern-driven, not tune-driven, so cross-rev aggregation gives a
more robust picture than any single rev (and avoids small-sample artifacts
like the 20.11-only sample claiming (2500, 0.20) at 5.4% strict cruise vs.
the cross-rev value of 2.8%).

Output columns:
    rpm_bp, load_bp,
    n_logs,
    total_samples,           total samples across all logs in any state
    strict_n, strict_pct,    strict-cruise filter (per SOP)
    active_n, active_pct,    broader filter (MPH>5)

Usage:
    python3 scripts/analysis/cell_residency.py
    python3 scripts/analysis/cell_residency.py --revs 20.9 20.10 20.11
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"
LOGS_DIR = REPO_ROOT / "logs"

# AVCS Cruise table grid — verified addresses from cross_rev_diff.py
RPM_BPS = [1000, 1100, 1350, 1600, 1900, 2200, 2500, 2800, 3000,
           3400, 3800, 4150, 4450, 4750, 5000, 5500]
LOAD_BPS = [0.20, 0.30, 0.50, 0.60, 0.70, 0.80, 0.90, 1.00, 1.10,
            1.20, 1.30, 1.50, 1.75, 2.00, 2.25, 2.50, 3.50, 4.00]

# Strict-cruise filter constants (per feedback_cruise_residency_method)
CRUISE_RPM_STD = 50
CRUISE_APP_STD = 1.0
CRUISE_THR_STD = 1.0
CRUISE_MIN_MPH = 20
WIN_1S = 25  # samples per second @ 25 Hz; old logs at 10 Hz get rolling adjusted


def _nearest_idx(values: np.ndarray, breakpoints: list) -> np.ndarray:
    arr = np.asarray(values, dtype=float)
    bps = np.asarray(breakpoints, dtype=float)
    out = np.full(len(arr), -1, dtype=int)
    valid = np.isfinite(arr)
    if valid.any():
        diffs = np.abs(arr[valid].reshape(-1, 1) - bps.reshape(1, -1))
        out[valid] = np.argmin(diffs, axis=1)
    return out


def compute_log_residency(df: pd.DataFrame, sample_rate: int = 25) -> dict:
    """Return per-cell sample counts under strict-cruise and active filters."""
    win = max(int(sample_rate), 5)
    rpm_std = df["RPM"].rolling(win, min_periods=win, center=True).std()
    app_std = df["Accelerator"].rolling(win, min_periods=win, center=True).std()
    thr_std = df["Throttle"].rolling(win, min_periods=win, center=True).std()

    strict = (
        (df["CL/OL"] == 8)
        & (df["MPH"] > CRUISE_MIN_MPH)
        & (rpm_std < CRUISE_RPM_STD)
        & (app_std < CRUISE_APP_STD)
        & (thr_std < CRUISE_THR_STD)
    )
    active = df["MPH"] > 5

    rpm_idx = _nearest_idx(df["RPM"].to_numpy(), RPM_BPS)
    load_idx = _nearest_idx(df["load"].to_numpy(), LOAD_BPS)

    out = {"strict": {}, "active": {}, "total_samples": int(len(df)),
           "strict_total": int(strict.sum()), "active_total": int(active.sum())}
    valid = (rpm_idx >= 0) & (load_idx >= 0)
    for ri in range(len(RPM_BPS)):
        for li in range(len(LOAD_BPS)):
            mask_cell = valid & (rpm_idx == ri) & (load_idx == li)
            out["strict"][(RPM_BPS[ri], LOAD_BPS[li])] = int((strict & mask_cell).sum())
            out["active"][(RPM_BPS[ri], LOAD_BPS[li])] = int((active & mask_cell).sum())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--revs", nargs="+",
                    help="Only aggregate these revs (default: all in rom_rev_map.csv)")
    ap.add_argument("--out", default=str(TRENDS_DIR / "cell_residency.csv"))
    args = ap.parse_args()

    # Import the ingest module's load_log + detect_sample_rate so we get
    # the same column-normalization the trends store uses
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "analysis"))
    import log_review_ingest as ing  # noqa: E402

    rev_map = pd.read_csv(LOGS_DIR / "rom_rev_map.csv", dtype={"rom_rev": str})
    if args.revs:
        rev_map = rev_map[rev_map["rom_rev"].isin(args.revs)]
    if not len(rev_map):
        sys.exit("no logs to process")

    # Aggregate per cell across all logs
    strict_total = {(r, l): 0 for r in RPM_BPS for l in LOAD_BPS}
    active_total = {(r, l): 0 for r in RPM_BPS for l in LOAD_BPS}
    strict_denom = 0
    active_denom = 0
    sample_total = 0
    n_logs = 0
    revs_used = set()

    for _, row in rev_map.iterrows():
        raw_path = row["log_path"]
        # Resolve actual file location (some logs live under logs/Older/)
        p = LOGS_DIR / raw_path
        if not p.exists():
            hits = list(LOGS_DIR.rglob(Path(raw_path).name))
            if hits:
                p = hits[0]
        if not p.exists():
            print(f"  warn: missing {raw_path}", file=sys.stderr)
            continue
        try:
            df = ing.load_log(p)
            # detect actual sample rate for this log (old logs are 10 Hz)
            sps = ing.detect_sample_rate(df["time"].to_numpy()) if "time" in df.columns else 25
            res = compute_log_residency(df, sample_rate=sps)
        except Exception as e:
            print(f"  warn: failed on {raw_path}: {e}", file=sys.stderr)
            continue

        for cell, n in res["strict"].items():
            strict_total[cell] += n
        for cell, n in res["active"].items():
            active_total[cell] += n
        strict_denom += res["strict_total"]
        active_denom += res["active_total"]
        sample_total += res["total_samples"]
        n_logs += 1
        revs_used.add(row["rom_rev"])
        print(f"  {row['rom_rev']:>12}  {raw_path:<40}  "
              f"{res['total_samples']:>7,} samples  "
              f"strict {res['strict_total']:>6,}  active {res['active_total']:>7,}")

    # Emit CSV
    rows = []
    for r in RPM_BPS:
        for l in LOAD_BPS:
            sn = strict_total[(r, l)]
            an = active_total[(r, l)]
            rows.append({
                "rpm_bp": r,
                "load_bp": l,
                "n_logs": n_logs,
                "total_samples": sample_total,
                "strict_n": sn,
                "strict_pct": round(100 * sn / max(strict_denom, 1), 4),
                "active_n": an,
                "active_pct": round(100 * an / max(active_denom, 1), 4),
                "above_1pct_strict": sn >= 0.01 * max(strict_denom, 1),
            })
    out_df = pd.DataFrame(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.out, index=False)
    print(f"\nWrote {args.out}")
    print(f"  Aggregated {n_logs} logs across revs: {sorted(revs_used)}")
    print(f"  Total samples: {sample_total:,}  strict cruise: {strict_denom:,}  active: {active_denom:,}")

    # Compact summary: which cells of interest are above/below 1% strict
    print("\nResidency rule summary (cells edited in proposed 20.12):")
    target_cells = [
        (2200, 0.20), (2500, 0.20), (2800, 0.20), (3000, 0.20), (3400, 0.20),
        (3800, 0.20), (4150, 0.20),
        (2200, 0.30), (2500, 0.30), (2800, 0.30), (3000, 0.30), (3400, 0.30),
    ]
    print(f"{'cell':>14}  {'strict %':>9}  {'verdict':>14}")
    for r, l in target_cells:
        row = out_df[(out_df["rpm_bp"] == r) & (out_df["load_bp"] == l)].iloc[0]
        verdict = "✓ above 1%" if row["above_1pct_strict"] else "✗ theater"
        if 0.005 <= row["strict_pct"] / 100 < 0.015:
            verdict = "⚠ borderline"
        print(f"  ({r}, {l:.2f})  {row['strict_pct']:>8.2f}%  {verdict:>14}")


if __name__ == "__main__":
    main()
