#!/usr/bin/env python3
"""
First-instance knock-fire rates by zone, per rev-mapped log.

Motivation (2026-06-07 review): the legacy "FBKC<0 samples/min" metric is
inflated by deep knock chains that park FBKC negative for long stretches —
it measures retard-holding time, not knock occurrence. The honest cross-rev
metric is FIRST-INSTANCE fires/min: count FBKC down-steps (diff <= -0.3 within
a contiguous recording segment), normalized by zone residency.

Per feedback_first_knock_cell_attribution: only the first FBKC<0 sample of an
event identifies the knock cell; subsequent samples carry the learned retard.

Zones:
  ghost = 2200-3300 RPM x load 1.0-1.4   (legacy ghost-knock zone)
  cusp  = 1600-3000 RPM x load 1.00-1.25 (cusp band per cusp_longitudinal.py)
  rect  = 2250-3150 RPM x load 1.05-1.40 (5th-gear passing rectangle, 6-21)

Both fires/min and the legacy FBKC<0 samp/min are emitted so the two can be
compared rev-over-rev.

Output: scripts/analysis/trends/zone_fire_rates.csv (full regeneration each
run — small file, no idempotency bookkeeping needed).

Usage:
    python3 scripts/analysis/ghost_zone_fires.py [--only-missing]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from log_review_ingest import load_log, detect_sample_rate  # noqa: E402

REPO_ROOT = SCRIPT_DIR.parents[1]
TRENDS_DIR = SCRIPT_DIR / "trends"
OUT = TRENDS_DIR / "zone_fire_rates.csv"

ZONES = {
    "ghost": dict(rpm=(2200, 3300), load=(1.0, 1.4)),
    "cusp": dict(rpm=(1600, 3000), load=(1.00, 1.25)),
    # 5th-gear passing rectangle, locked 6-21 (project_5th_gear_passing_knock).
    # Added 2026-07-12 so cross-rev rect claims come from the store, not ad-hoc scripts.
    "rect": dict(rpm=(2250, 3150), load=(1.05, 1.40)),
}


def one_log(path: Path, log_date: str, rom_rev: str) -> list[dict]:
    df = load_log(path)
    need = {"time", "RPM", "load", "FBKC"}
    if not need.issubset(df.columns):
        return []
    sps = detect_sample_rate(df["time"].to_numpy())
    dt_min = 1.0 / sps / 60.0
    rdt = df["time"].diff()
    # fire = FBKC down-step inside a contiguous segment (no clock jump).
    # Counts EVERY deepening step, incl. within an active retard chain.
    fire = (df["FBKC"].diff() <= -0.3) & (rdt > 0) & (rdt < 1)
    # onset = down-step FROM ZERO — the strict first-instance event definition
    # per feedback_first_knock_cell_attribution. Discovered 2026-07-15: the 7-12
    # review's "matched cross-log" rates (rect 1.97/3.41 per min) were onsets;
    # this store's fires_per_min (3.38/6.16) were all-steps. Both are now emitted.
    onset = fire & (df["FBKC"].shift(1) == 0)
    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    rows = []
    for zname, z in ZONES.items():
        m = df["RPM"].between(*z["rpm"]) & df["load"].between(*z["load"])
        res_min = m.sum() * dt_min
        n_fires = int((fire & m).sum())
        n_onsets = int((onset & m).sum())
        n_neg = int((df["FBKC"] < 0)[m].sum())
        rows.append(dict(
            log_date=log_date, rom_rev=rom_rev, log_path=rel, zone=zname,
            residency_min=round(res_min, 3), n_fires=n_fires,
            fires_per_min=round(n_fires / res_min, 3) if res_min > 0.05 else np.nan,
            n_onsets=n_onsets,
            onsets_per_min=round(n_onsets / res_min, 3) if res_min > 0.05 else np.nan,
            fbkc_neg_samples=n_neg,
            fbkc_neg_samp_per_min=round(n_neg * dt_min / res_min / dt_min, 1) if res_min > 0.05 else np.nan,
            min_fbkc_in_zone=float(df.loc[m, "FBKC"].min()) if m.any() else np.nan,
        ))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-missing", action="store_true",
                    help="only process logs not already in the output CSV")
    args = ap.parse_args()
    m = pd.read_csv(REPO_ROOT / "logs" / "rom_rev_map.csv")
    done = set()
    out_rows: list[dict] = []
    if args.only_missing and OUT.exists():
        prev = pd.read_csv(OUT)
        out_rows = prev.to_dict("records")
        done = set(prev["log_path"])
    for _, r in m.iterrows():
        p = REPO_ROOT / "logs" / r["log_path"]
        rel = f"logs/{r['log_path']}"
        if rel in done:
            continue
        if not p.exists():
            print(f"  SKIP (missing): {rel}", file=sys.stderr)
       