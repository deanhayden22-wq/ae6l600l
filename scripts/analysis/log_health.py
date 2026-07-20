#!/usr/bin/env python3
"""
Per-log health + environment covariates -> trends/log_health.csv
                + matched-cell trim   -> trends/total_trim_by_vcell.csv

Motivation (2026-07-12 review): cross-log knock/fueling comparisons kept
needing context that lived nowhere — the 7-12 vs 6-21 knock elevation
(+73% rect fires/min on the SAME bin) took manual work to attribute to a
hot+AC day, and the FLKC tier engagement (7 -> 518 decrements) wasn't a
column anywhere. One row per rev-mapped log:

  Environment:   iat_med / iat_p95 / iat_max, ect_med, atm_med, egt_min (ohms,
                 lower = hotter; NON-DECEL only — APP>2 and IPW>0, because
                 fuel-cut decel pegs the sensor hot and would own every floor)
  Drive mix:     duration_min, pct_highway (MPH>50), pct_boost (mrp>5)
  Knock:         fbkc_fires (first-instance, whole log), fbkc_deep (depth<=-3),
                 fbkc_deep_resume / fbkc_fires_resume (onset within 5 s of an
                 IPW==0 exit — the DFCO-resume family), fbkc_min, iam_min,
                 fbkc_retard_pct (% samples holding FBKC<0 — retard DUTY, the
                 delay-70 mechanism, distinct from event frequency),
                 knock_recov_med_s (median s from onset back to FBKC==0),
                 knock_unrecovered (events still negative at log end),
                 cam_transit_onset_pct (% of onsets where |Δavcs| > 4° over the
                 prior 0.5 s — tests the cam-transit hypothesis per log)
  FLKC tier:     flkc_decrements, flkc_min, flkc_neg_pct, flkc_end_zero
  Fuel trims:    afl_med (warm), afl_end (median of last 5%),
                 total_trim_cruise_med (AFC+AFL, warm steady CL cruise:
                 CL/OL==8, MPH>20, 1s RPM std<50, Throttle>2, mrp>-8),
                 total_trim_matched_med (median of per-V-cell trim medians over
                 MAF(V) 1.8-3.0 V cells with n>=100 — the MATCHED-POINT fueling
                 error; robust to AFL/AFC redistribution AND to drive-mix
                 weighting, unlike total_trim_cruise_med. Per-cell rows go to
                 total_trim_by_vcell.csv for cross-log matched comparisons.)
  Injectors:     idc_max, idc_p99, idc_s_over85 (seconds above the 85% flag —
                 peak alone overweights single samples), maf_v_max

First-instance fire = FBKC<0 where previous sample FBKC==0, not across a
segment boundary. Depth = min FBKC until recovery to 0.

Era note: fueling columns are NOT comparable across the PCV-fix boundary
(all logs <= 6-15 had a lean PCV leak; 6-21 first clean log —
project_pcv_leak_confounder). Knock/IDC/env columns are continuous.
iam_min filtered to CL/OL in {8,10} (drops key-on init state-0 + warmup-7). A surviving <1 is REAL sustained knock (4-24 20.8: IAM 0.5 for 26s at 4250-4800 RPM, states 8/10).

Full regeneration each run (small output). Usage:
    python3 scripts/analysis/log_health.py [--only-missing] [--budget N]

--budget N processes at most N missing logs per invocation (resumable with
--only-missing; for the 45 s remote-bridge window use --budget 8).
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
OUT_VCELL = TRENDS_DIR / "total_trim_by_vcell.csv"

WARM_ECT = 170.0
DEEP = -3.0
RESUME_S = 5.0
IDC_FLAG = 85.0
CAM_TRANSIT_DEG = 4.0        # |Δavcs| over 0.5 s that counts as "in transit"
VCELL_EDGES = np.round(np.arange(1.2, 3.6 + 1e-9, 0.2), 1)
MATCHED_LO, MATCHED_HI = 1.8, 3.0   # cruise flow band for the matched summary
VCELL_MIN_N = 100


def one_log(path: Path, log_date: str, rom_rev: str):
    df = load_log(path)
    need = {"time", "RPM", "load", "FBKC"}
    if not need.issubset(df.columns):
        return None, []
    sps = detect_sample_rate(df["time"].to_numpy())
    n = len(df)
    dur_min = n / sps / 60.0
    rdt = df["time"].diff()
    seg_ok = (rdt > 0) & (rdt < 1)  # inside a contiguous recording segment

    def med(col):
        return float(df[col].median()) if col in df.columns else np.nan

    warm = df["ECT"] > WARM_ECT if "ECT" in df.columns else pd.Series(True, index=df.index)

    # --- first-instance FBKC events + depth + recovery + resume attribution
    fb = df["FBKC"].to_numpy()
    onset = (fb < 0) & (np.roll(fb, 1) == 0)
    onset[0] = False
    onset &= seg_ok.to_numpy()
    idx = np.where(onset)[0]
    depths, recov_s = [], []
    unrecovered = 0
    for i in idx:
        j = i
        while j < n - 1 and fb[j] < 0:
            j += 1
        depths.append(fb[i:j].min() if j > i else fb[i])
        if fb[j] < 0:            # ran off the end of the log still negative
            unrecovered += 1
        else:
            recov_s.append((j - i) / sps)
    depths = np.array(depths) if len(idx) else np.array([])
    deep_mask = depths <= DEEP if len(idx) else np.array([], dtype=bool)
    retard_pct = float((fb < 0).mean() * 100)
    recov_med = float(np.median(recov_s)) if recov_s else np.nan

    # onsets within RESUME_S of an IPW==0 exit (any depth + deep-only)
    deep_resume = 0
    fires_resume = 0
    if "IPW" in df.columns and len(idx):
        ipw0 = np.where(df["IPW"].to_numpy() == 0)[0]
        lim = RESUME_S * sps
        for i, dp in zip(idx, deep_mask):
            k = np.searchsorted(ipw0, i) - 1
            if k >= 0 and (i - ipw0[k]) <= lim:
                fires_resume += 1
                if dp:
                    deep_resume += 1

    # cam-transit share of onsets
    cam_transit_pct = np.nan
    if "avcs" in df.columns and len(idx):
        av = df["avcs"].to_numpy(dtype=float)
        w = max(1, int(round(sps / 2)))
        hits = 0
        for i in idx:
            a, b = max(0, i - w), i
            if abs(av[b] - av[a]) > CAM_TRANSIT_DEG:
                hits += 1
        cam_transit_pct = round(100 * hits / len(idx), 1)

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
    matched_med = np.nan
    vcell_rows = []
    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    if {"AFC", "AFL", "CL/OL", "MPH", "Throttle", "mrp"}.issubset(df.columns):
        rstd = df["RPM"].rolling(int(sps)).std()
        steady = (warm & (df["CL/OL"] == 8) & (df["MPH"] > 20) & (rstd < 50)
                  & (df["Throttle"] > 2) & (df["mrp"] > -8))
        if steady.sum() >= 500:
            ttc = float((df.loc[steady, "AFC"] + df.loc[steady, "AFL"]).median())
        # matched-cell trim on the MAF(V) grid (V axis stable since 20.11 —
        # the safe join key per reference_maf_analysis_methodology)
        if "MAF(V)" in df.columns and steady.sum() >= 500:
            tot = df.loc[steady, "AFC"] + df.loc[steady, "AFL"]
            vc = pd.cut(df.loc[steady, "MAF(V)"], VCELL_EDGES)
            cellmeds = []
            for cell, g in tot.groupby(vc, observed=True):
                if len(g) < VCELL_MIN_N:
                    continue
                cm = float(g.median())
                vcell_rows.append(dict(
                    log_date=log_date, rom_rev=rom_rev, log_path=rel,
                    v_lo=float(cell.left), v_hi=float(cell.right),
                    n=int(len(g)), trim_med=round(cm, 4),
                ))
                if MATCHED_LO <= cell.left and cell.right <= MATCHED_HI:
                    cellmeds.append(cm)
            if cellmeds:
                matched_med = float(np.median(cellmeds))

    row = dict(
        log_date=log_date, rom_rev=rom_rev, log_path=rel,
        duration_min=round(dur_min, 1),
        iat_med=med("IAT"), iat_p95=float(df["IAT"].quantile(.95)) if "IAT" in df.columns else np.nan,
        iat_max=float(df["IAT"].max()) if "IAT" in df.columns else np.nan,
        ect_med=med("ECT"), atm_med=med("ATM(psi)"),
        egt_min=(float(df.loc[(df["Accelerator"] > 2) & (df["IPW"] > 0), "EGT"].min())
                 if {"EGT", "Accelerator", "IPW"}.issubset(df.columns)
                 and ((df["Accelerator"] > 2) & (df["IPW"] > 0)).any() else np.nan),
        pct_highway=round(float((df["MPH"] > 50).mean() * 100), 1) if "MPH" in df.columns else np.nan,
        pct_boost=round(float((df["mrp"] > 5).mean() * 100), 2) if "mrp" in df.columns else np.nan,
        fbkc_fires=int(len(idx)), fbkc_deep=int(deep_mask.sum()),
        fbkc_deep_resume=int(deep_resume), fbkc_fires_resume=int(fires_resume),
        fbkc_min=float(np.nanmin(fb)) if n else np.nan,
        iam_min=float(df.loc[df["CL/OL"].isin([8,10]),"IAM"].min()) if ("IAM" in df.columns and "CL/OL" in df.columns) else np.nan,  # {8,10} only: drop key-on init(0)+warmup(7); survivors are REAL (4-24 20.8 = 0.5 sustained)
        fbkc_retard_pct=round(retard_pct, 3),
        knock_recov_med_s=round(recov_med, 2) if recov_med == recov_med else np.nan,
        knock_unrecovered=int(unrecovered),
        cam_transit_onset_pct=cam_transit_pct,
        flkc_decrements=dec, flkc_min=flkc_min,
        flkc_neg_pct=round(flkc_neg_pct, 2) if flkc_neg_pct == flkc_neg_pct else np.nan,
        flkc_end_zero=flkc_end_zero,
        afl_med=afl_med, afl_end=afl_end, total_trim_cruise_med=ttc,
        total_trim_matched_med=round(matched_med, 4) if matched_med == matched_med else np.nan,
        idc_max=float(df["IDC"].max()) if "IDC" in df.columns else np.nan,
        idc_p99=float(df["IDC"].quantile(.99)) if "IDC" in df.columns else np.nan,
        idc_s_over85=round(float((df["IDC"] > IDC_FLAG).sum() / sps), 2) if "IDC" in df.columns else np.nan,
        maf_v_max=float(df["MAF(V)"].max()) if "MAF(V)" in df.columns else np.nan,
    )
    return row, vcell_rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-missing", action="store_true")
    ap.add_argument("--budget", type=int, default=0,
                    help="max logs to process this invocation (0 = unlimited)")
    args = ap.parse_args()
    m = pd.read_csv(REPO_ROOT / "logs" / "rom_rev_map.csv")
    done = set()
    out_rows: list[dict] = []
    vc_rows: list[dict] = []
    if args.only_missing and OUT.exists():
        prev = pd.read_csv(OUT)
        out_rows = prev.to_dict("records")
        done = set(prev["log_path"])
        if OUT_VCELL.exists():
            pv = pd.read_csv(OUT_VCELL)
            vc_rows = pv[pv["log_path"].isin(done)].to_dict("records")
    budget = args.budget if args.budget > 0 else 10**9
    for _, r in m.iterrows():
        if budget == 0:
            print("BUDGET-STOP", file=sys.stderr)
            break
        p = REPO_ROOT / "logs" / r["log_path"]
        rel = f"logs/{r['log_path']}"
        if rel in done:
            continue
        if not p.exists():
            print(f"  SKIP (missing): {rel}", file=sys.stderr)
            continue
        row, vcr = one_log(p, str(r["log_date"]), str(r["rom_rev"]))
        if row is None:
            print(f"  SKIP (columns): {rel}", file=sys.stderr)
            continue
        out_rows.append(row)
        vc_rows.extend(vcr)
        budget -= 1
        print(f"{row['log_date']} {row['rom_rev']:>8s} {row['duration_min']:7.1f} min  "
              f"IATmed {row['iat_med']}  fires {row['fbkc_fires']:3d} deep {row['fbkc_deep']:2d} "
              f"duty {row['fbkc_retard_pct']:.2f}%  recov {row['knock_recov_med_s']}s  "
              f"matched-trim {row['total_trim_matched_med']}")
    pd.DataFrame(out_rows).to_csv(OUT, index=False)
    pd.DataFrame(vc_rows).to_csv(OUT_VCELL, index=False)
    remaining = sum(1 for _, r in m.iterrows()
                    if f"logs/{r['log_path']}" not in {x["log_path"] for x in out_rows}
                    and (REPO_ROOT / "logs" / r["log_path"]).exists())
    print(f"\nwrote {OUT} ({len(out_rows)} rows) + {OUT_VCELL} ({len(vc_rows)} rows), remaining {remaining}")


if __name__ == "__main__":
    main()
