#!/usr/bin/env python3
"""
Per-log health + environment covariates -> trends/log_health.csv.

Motivation (2026-07-12 review): cross-log knock/fueling comparisons kept
needing context that lived nowhere — the 7-12 vs 6-21 knock elevation
(+73% rect fires/min on the SAME bin) took manual work to attribute to a
hot+AC day, and the FLKC tier engagement (7 -> 518 decrements) wasn't a
column anywhere. One row per rev-mapped log:

  Environment:   iat_med / iat_p95 / iat_max, ect_med, atm_med
  Drive mix:     duration_min, pct_highway (MPH>50), pct_boost (mrp>5)
  Knock:         fbkc_fires (first-instance, whole log), fbkc_deep (depth<=-3),
                 fbkc_deep_resume (deep onset within 5 s of IPW==0 exit —
                 the DFCO-resume wall-wetting family, project_dfco_resume_recovery),
                 fbkc_min, iam_min
  FLKC tier:     flkc_decrements, flkc_min, flkc_neg_pct, flkc_end_zero
  Fuel trims:    afl_med (warm), afl_end (median of last 5%),
                 total_trim_cruise_med (AFC+AFL, warm steady CL cruise:
                 CL/OL==8, MPH>20, 1s RPM std<50, Throttle>2, mrp>-8 —
                 the real fueling-error signal; AFL alone redistributes)
  Injectors:     idc_max, idc_p99, maf_v_max

First-instance fire = FBKC<0 where previous sample FBKC==0, not across a
segment boundary. Depth = min FBKC until recovery to 0.

Era note: fueling columns are NOT comparable across the PCV-fix boundary
(all logs <= 6-15 had a lean PCV leak; 6-21 first clean log —
project_pcv_leak_confounder). Knock/IDC/env columns are continuous.

Full regeneration each run (small output). Usage:
    python3 scripts/analysis/log_health.py [--only-missing]
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
OUT = TRENDS_DIR / "log_health.csv"

WARM_ECT = 170.0
DEEP = -3.0
RESUME_S = 5.0


def one_log(path: Path, log_date: str, rom_rev: str) -> dict | None:
    df = load_log(path)
    need = {"time", "RPM", "load", "FBKC"}
    if not need.issubset(df.columns):
        return None
    sps = detect_sample_rate(df["time"].to_numpy())
    n = len(df)
    dur_min = n / sps / 60.0
    rdt = df["time"].diff()
    seg_ok = (rdt > 0) & (rdt < 1)  # inside a contiguous recording segment

    def med(col):
        return float(df[col].median()) if col in df.columns else np.nan

    warm = df["ECT"] > WARM_ECT if "ECT" in df.columns else pd.Series(True, index=df.index)

    # --- first-instance FBKC events + depth + resume attribution
    fb = df["FBKC"].to_numpy()
    onset = (fb < 0) & (np.roll(fb, 1) == 0)
    onset[0] = False
    onset &= seg_ok.to_numpy()
    idx = np.where(onset)[0]
    depths = []
    for i in idx:
        j = i
        while j < n - 1 and fb[j] < 0:
            j += 1
        depths.append(fb[i:j].min() if j > i else fb[i])
    depths = np.array(depths) if len(idx) else np.array([])
    deep_mask = depths <= DEEP if len(idx) else np.array([], dtype=bool)

    # samples since last IPW==0 (DFCO) at each onset
    deep_resume = 0
    if "IPW" in df.columns and len(idx):
        ipw0 = np.where(df["IPW"].to_numpy() == 0)[0]
        lim = RESUME_S * sps
        for i, dp in zip(idx, deep_mask):
            if not dp:
                continue
            k = np.searchsorted(ipw0, i) - 1
            if k >= 0 and (i - ipw0[k]) <= lim:
                deep_resume += 1

    # --- FLKC tier
    if "FLKC" in df.columns:
        fl = df["FLKC"].to_numpy()
        dec = int(((np.diff(fl) < 0) & seg_ok.to_numpy()[1:]).sum())
        flkc_min = float(np.nanmin(fl))
        flkc_neg_pct = float((fl < 0).mean() * 100)
        flkc_end_zero = bool(fl[-1] == 0)
    else:
        dec, flkc_min, flkc_neg_pct, flkc_end_zero = np.nan, np.nan, np.nan, np.nan

    # --- trims
    afl_med = float(df.loc[warm, "AFL"].median()) if "AFL" in df.columns else np.nan
    afl_end = float(df["AFL"].iloc[-max(1, n // 20):].median()) if "AFL" in df.columns else np.nan
    ttc = np.nan
    if {"AFC", "AFL", "CL/OL", "MPH", "Throttle", "mrp"}.issubset(df.columns):
        rstd = df["RPM"].rolling(int(sps)).std()
        steady = (warm & (df["CL/OL"] == 8) & (df["MPH"] > 20) & (rstd < 50)
                  & (df["Throttle"] > 2) & (df["mrp"] > -8))
        if steady.sum() >= 500:
            ttc = float((df.loc[steady, "AFC"] + df.loc[steady, "AFL"]).median())

    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    return dict(
        log_date=log_date, rom_rev=rom_rev, log_path=rel,
        duration_min=round(dur_min, 1),
        iat_med=med("IAT"), iat_p95=float(df["IAT"].quantile(.95)) if "IAT" in df.columns else np.nan,
        iat_max=float(df["IAT"].max()) if "IAT" in df.columns else np.nan,
        ect_med=med("ECT"), atm_med=med("ATM(psi)"),
        pct_highway=round(float((df["MPH"] > 50).mean() * 100), 1) if "MPH" in df.columns else np.nan,
        pct_boost=round(float((df["mrp"] > 5).mean() * 100), 2) if "mrp" in df.columns else np.nan,
        fbkc_fires=int(len(idx)), fbkc_deep=int(deep_mask.sum()),
        fbkc_deep_resume=int(deep_resume),
        fbkc_min=float(np.nanmin(fb)) if n else np.nan,
        iam_min=float(df["IAM"].min()) if "IAM" in df.columns else np.nan,
        flkc_decrements=dec, flkc_min=flkc_min,
        flkc_neg_pct=round(flkc_neg_pct, 2) if flkc_neg_pct == flkc_neg_pct else np.nan,
        flkc_end_zero=flkc_end_zero,
        afl_med=afl_med, afl_end=afl_end, total_trim_cruise_med=ttc,
        idc_max=float(df["IDC"].max()) if "IDC" in df.columns else np.nan,
        idc_p99=float(df["IDC"].quantile(.99)) if "IDC" in df.columns else np.nan,
        maf_v_max=float(df["MAF(V)"].max()) if "MAF(V)" in df.columns else np.nan,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-missing", action="store_true")
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
            continue
        row = one_log(p, str(r["log_date"]), str(r["rom_rev"]))
        if row is None:
            print(f"  SKIP (columns): {rel}", file=sys.stderr)
            continue
        out_rows.append(row)
        print(f"{row['log_date']} {row['rom_rev']:>8s} {row['duration_min']:7.1f} min  "
              f"IATmed {row['iat_med']}  fires {row['fbkc_fires']:3d} deep {row['fbkc_deep']:2d} "
              f"resume {row['fbkc_deep_resume']:2d}  FLKCdec {row['flkc_decrements']}  "
              f"IDCmax {row['idc_max']}")
    pd.DataFrame(out_rows).to_csv(OUT, index=False)
    print(f"\nwrote {OUT} ({len(out_rows)} rows)")


if __name__ == "__main__":
    main()
