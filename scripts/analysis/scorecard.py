#!/usr/bin/env python3
"""
Per-(rom_rev, thread) tuning scorecard.

Reads the per-metric trend CSVs in scripts/analysis/trends/ and emits a
scorecard with absolute, Δ-from-baseline, and Δ-from-prior-rev columns.

Non-destructive: this script never modifies the source trends CSVs.
It only writes:
  scripts/analysis/trends/scorecard.csv          (append-only history)
  scripts/analysis/trends/scorecard_latest.csv   (most-recent run, overwritten)
  scripts/analysis/trends/log_durations.csv      (cached log durations)

Threads (see docs/methodology/ for definitions):
  pedal_throttle  — throttle hunt + RPM swing events / min
  avcs            — AVCS oscillation events / min
  timing_sum      — knock events (FBKC + FLKC) / min + min depth + timing osc / min
                    (timing analyzed on the Sum map BTC + KCA·IAM per
                    docs/open-issues.md decision 2026-05-08)
  wgdc            — pull-ramp target attainment + peak mrp + wgdc-pegged count
  ol_fueling      — AFR osc / min, FFB-wbo2 div / min, sample-weighted MAF corr
  cross_thread    — stutter signature: 500 ms windows with ≥2 distinct signals

Baseline: stock (the earliest fully-comparable rev; MerpMod port has never
been flashed, so stock is this car's actual reference point).

Usage:
    python scorecard.py
    python scorecard.py --baseline 20.7
    python scorecard.py --recompute-durations
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"
LOGS_DIR = REPO_ROOT / "logs"

# Canonical rev order. Append new revs here.
REV_ORDER = [
    "old_2023_base", "stock", "20.7", "20.8", "20.9", "20.10", "20.11", "20.12",
]
DEFAULT_BASELINE = "stock"

# Stutter signature: ≥N distinct signal types within window_s of each other
STUTTER_SIG_MIN_SIGNALS = 2
STUTTER_SIG_WINDOW_S = 0.5

DEFAULT_SAMPLES_PER_SEC = 25


# ---------- sample-rate / duration helpers ----------

def detect_sample_rate(time_arr):
    """Adapted from log_review_ingest.detect_sample_rate.

    Robust to fractional-second time (0.04s @ 25 Hz),
    integer-second time (3-21 style multiple samples per second),
    and stitched sessions where time resets mid-log.
    """
    arr = np.asarray(time_arr, dtype=float)
    arr = arr[np.isfinite(arr)]
    if len(arr) < 2:
        return DEFAULT_SAMPLES_PER_SEC
    diffs = np.diff(arr)
    pos = diffs[(diffs > 0) & (diffs < 60)]
    if len(pos) > 0:
        median_dt = float(np.median(pos))
        if 0 < median_dt < 1:
            return max(int(round(1.0 / median_dt)), 1)
    sec = np.floor(arr).astype(int)
    _, counts = np.unique(sec, return_counts=True)
    if len(counts) == 0:
        return DEFAULT_SAMPLES_PER_SEC
    rate = int(round(np.median(counts)))
    return rate if rate > 0 else DEFAULT_SAMPLES_PER_SEC


def _read_time_col(path: Path) -> np.ndarray:
    """Read just the time column from a log CSV, robust to old/new schema."""
    # Old logger: "Time"; new logger: "time"; pre-MerpMod stock: "time".
    df = pd.read_csv(
        path,
        usecols=lambda c: c.strip().lower() == "time",
        low_memory=False,
    )
    if df.empty or df.shape[1] == 0:
        return np.array([])
    col = df.iloc[:, 0]
    if col.dtype == object:
        col = pd.to_numeric(col, errors="coerce")
    return col.to_numpy(dtype=float)


def _resolve_log_path(rel_path: str) -> Path | None:
    """Find a log file from whatever the rev_map / trends CSV recorded.

    Handles: absolute paths, "logs/..."-prefixed, bare filenames, and the
    case where the bare name actually lives in logs/Older/."""
    p = Path(rel_path)
    if p.is_absolute() and p.exists():
        return p
    # Try as-is relative to repo root
    if (REPO_ROOT / p).exists():
        return REPO_ROOT / p
    # Try with logs/ prefix
    if not str(p).startswith("logs/"):
        if (LOGS_DIR / p).exists():
            return LOGS_DIR / p
        # Bare name — search logs/**/ for the filename
        matches = list(LOGS_DIR.rglob(p.name))
        if matches:
            return matches[0]
    # logs/-prefixed but file isn't there — try stripping prefix and globbing
    bare = p.name
    matches = list(LOGS_DIR.rglob(bare))
    if matches:
        return matches[0]
    return None


def log_duration_minutes(rel_path: str) -> tuple[float, int, int]:
    """Return (minutes, n_rows, samples_per_sec) for a log path."""
    full = _resolve_log_path(rel_path)
    if full is None:
        return (float("nan"), 0, DEFAULT_SAMPLES_PER_SEC)
    try:
        t = _read_time_col(full)
        n_rows = int(len(t))
        sps = detect_sample_rate(t) if n_rows > 1 else DEFAULT_SAMPLES_PER_SEC
        minutes = n_rows / sps / 60.0 if sps > 0 else float("nan")
        return (float(minutes), n_rows, int(sps))
    except Exception as e:
        print(f"  warn: duration calc failed for {rel_path}: {e}", file=sys.stderr)
        return (float("nan"), 0, DEFAULT_SAMPLES_PER_SEC)


def compute_log_durations(rev_map: pd.DataFrame, cache_path: Path,
                          recompute: bool = False) -> pd.DataFrame:
    """Build per-log duration table. Cached unless --recompute-durations.

    Stores log_path in the trends-CSV-normalized form ("logs/..."), so it
    joins directly against the per-metric trends CSVs.
    """
    # Normalize rev_map paths to the "logs/..." form used by trends CSVs
    norm = rev_map.copy()
    norm["log_path_trends"] = norm["log_path"].apply(
        lambda p: p if str(p).startswith("logs/") else f"logs/{p}"
    )

    if cache_path.exists() and not recompute:
        cached = pd.read_csv(cache_path)
        have = set(cached["log_path"])
        need = set(norm["log_path_trends"]) - have
        if not need:
            return cached
        new_rows = []
        for trends_path in need:
            raw = norm[norm["log_path_trends"] == trends_path]["log_path"].iloc[0]
            mins, n, sps = log_duration_minutes(raw)
            new_rows.append({"log_path": trends_path, "minutes": mins,
                             "n_rows": n, "samples_per_sec": sps})
        out = pd.concat([cached, pd.DataFrame(new_rows)], ignore_index=True)
    else:
        rows = []
        for _, r in norm.iterrows():
            mins, n, sps = log_duration_minutes(r["log_path"])
            rows.append({"log_path": r["log_path_trends"], "minutes": mins,
                         "n_rows": n, "samples_per_sec": sps})
        out = pd.DataFrame(rows)
    out.to_csv(cache_path, index=False)
    return out


# ---------- metric extractors ----------

def _normalized_rev_map(rev_map: pd.DataFrame) -> pd.DataFrame:
    out = rev_map.copy()
    out["log_path"] = out["log_path"].apply(
        lambda p: p if str(p).startswith("logs/") else f"logs/{p}"
    )
    return out[["log_path", "rom_rev", "log_date"]]


def m_stutter_rates(stutter_df: pd.DataFrame, durations: pd.DataFrame,
                    rev_map: pd.DataFrame) -> pd.DataFrame:
    """Per-rev × signal events/min.

    Returns columns: rom_rev, signal, n, minutes, events_per_min
    """
    by_path = (stutter_df.groupby(["log_path", "signal"]).size()
               .reset_index(name="n"))
    by_path = by_path.merge(durations[["log_path", "minutes"]],
                            on="log_path", how="left")
    by_path = by_path.merge(rev_map[["log_path", "rom_rev"]],
                            on="log_path", how="left")

    # rev-level minutes = sum of per-log minutes (distinct logs only)
    log_mins = by_path.drop_duplicates("log_path")[["rom_rev", "minutes"]]
    rev_mins = log_mins.groupby("rom_rev")["minutes"].sum().to_dict()

    rev_sig = by_path.groupby(["rom_rev", "signal"])["n"].sum().reset_index()
    rev_sig["minutes"] = rev_sig["rom_rev"].map(rev_mins)
    rev_sig["events_per_min"] = rev_sig["n"] / rev_sig["minutes"]
    return rev_sig


def m_stutter_signature(stutter_df: pd.DataFrame, durations: pd.DataFrame,
                        rev_map: pd.DataFrame) -> pd.DataFrame:
    """Count ≥2-distinct-signal clusters within STUTTER_SIG_WINDOW_S.

    Algorithm per log:
      1. Sort events by start_time
      2. Slide forward; gather all events within window from anchor
      3. If ≥STUTTER_SIG_MIN_SIGNALS distinct signal types → 1 signature event,
         mark cluster members consumed (so the same event isn't double-counted
         when the next anchor is the next unconsumed event)
      4. Advance anchor to first unconsumed event past the cluster
    """
    sig_rows = []
    for log_path, grp in stutter_df.groupby("log_path"):
        grp = grp.sort_values("start_time").reset_index(drop=True)
        n = len(grp)
        used = np.zeros(n, dtype=bool)
        sig_count = 0
        i = 0
        while i < n:
            if used[i]:
                i += 1
                continue
            t0 = grp.loc[i, "start_time"]
            members = [i]
            sigs = {grp.loc[i, "signal"]}
            j = i + 1
            while j < n and (grp.loc[j, "start_time"] - t0) <= STUTTER_SIG_WINDOW_S:
                if not used[j]:
                    members.append(j)
                    sigs.add(grp.loc[j, "signal"])
                j += 1
            if len(sigs) >= STUTTER_SIG_MIN_SIGNALS:
                sig_count += 1
                for m in members:
                    used[m] = True
                i = j  # skip past the cluster
            else:
                i += 1
        sig_rows.append({"log_path": log_path, "n_signature_events": sig_count})

    sig_df = pd.DataFrame(sig_rows)
    sig_df = sig_df.merge(durations[["log_path", "minutes"]],
                          on="log_path", how="left")
    sig_df = sig_df.merge(rev_map[["log_path", "rom_rev"]],
                          on="log_path", how="left")
    out = sig_df.groupby("rom_rev").agg(
        n=("n_signature_events", "sum"),
        minutes=("minutes", "sum"),
    ).reset_index()
    out["events_per_min"] = out["n"] / out["minutes"]
    return out


def m_knock_rates(knock_df: pd.DataFrame, durations: pd.DataFrame,
                  rev_map: pd.DataFrame) -> pd.DataFrame:
    """Per-rev FBKC and FLKC totals / min, plus deepest FBKC observed."""
    # rev-level minutes from rev_map join (one row per log)
    rev_log_mins = rev_map.merge(durations[["log_path", "minutes"]],
                                 on="log_path", how="left")
    rev_mins = rev_log_mins.groupby("rom_rev")["minutes"].sum().to_dict()

    agg = knock_df.groupby("rom_rev").agg(
        fbkc_events=("event_count_fbkc", "sum"),
        flkc_events=("event_count_flkc", "sum"),
        fbkc_samps=("sample_count_fbkc_neg", "sum"),
        flkc_samps=("sample_count_flkc_decr", "sum"),
        min_fbkc=("min_fbkc", "min"),
    ).reset_index()
    agg["minutes"] = agg["rom_rev"].map(rev_mins)
    agg["fbkc_events_per_min"] = agg["fbkc_events"] / agg["minutes"]
    agg["flkc_events_per_min"] = agg["flkc_events"] / agg["minutes"]
    agg["total_knock_events_per_min"] = (
        (agg["fbkc_events"].fillna(0) + agg["flkc_events"].fillna(0))
        / agg["minutes"]
    )
    return agg


def m_pull_ramps_rev(ramps_df: pd.DataFrame) -> pd.DataFrame:
    """Per-rev means across captured pull ramps."""
    agg = ramps_df.groupby("rom_rev").agg(
        n_pulls=("pull_id", "count"),
        mean_target_attainment=("target_attainment", "mean"),
        mean_peak_mrp=("peak_mrp", "mean"),
        wgdc_pegged=("wgdc_max", lambda s: int((s >= 95).sum())),
    ).reset_index()
    return agg


def m_maf_corr_mean(maf_df: pd.DataFrame) -> pd.DataFrame:
    """Sample-weighted mean (and mean-abs) of per-cell mean_correction."""
    rows = []
    for rev, grp in maf_df.groupby("rom_rev"):
        valid = grp[grp["sample_count"] > 0].copy()
        w = valid["sample_count"]
        wsum = float(w.sum())
        if wsum > 0:
            mean_c = float((valid["mean_correction"] * w).sum() / wsum)
            mean_abs_c = float((valid["mean_correction"].abs() * w).sum() / wsum)
        else:
            mean_c, mean_abs_c = (float("nan"),) * 2
        rows.append({
            "rom_rev": rev,
            "maf_corr_mean": mean_c,
            "maf_corr_mean_abs": mean_abs_c,
            "maf_samples": int(wsum),
        })
    return pd.DataFrame(rows)


# ---------- assembly ----------

def _rev_sort_key(s: pd.Series) -> pd.Series:
    return s.map(lambda x: REV_ORDER.index(x) if x in REV_ORDER else 999)


def assemble_scorecard(stutter_rates, stutter_sig, knock_rates,
                       ramps_rev, maf_rev) -> pd.DataFrame:
    """Emit one row per (rom_rev, thread, metric)."""
    rows = []

    def add(rev, thread, metric, value, **extras):
        rows.append({"rom_rev": rev, "thread": thread, "metric": metric,
                     "value": value, **extras})

    revs_set = set()
    for df, col in [
        (stutter_rates, "rom_rev"), (stutter_sig, "rom_rev"),
        (knock_rates, "rom_rev"), (ramps_rev, "rom_rev"),
        (maf_rev, "rom_rev"),
    ]:
        revs_set.update(df[col].dropna().tolist())
    revs = sorted(revs_set,
                  key=lambda r: REV_ORDER.index(r) if r in REV_ORDER else 999)

    for rev in revs:
        # ----- pedal_throttle -----
        for sig, metric in [
            ("throttle_hunt_at_steady_app", "throttle_hunt_per_min"),
            ("rpm_swing_steady_tps",        "rpm_swing_per_min"),
        ]:
            sub = stutter_rates[(stutter_rates["rom_rev"] == rev)
                                & (stutter_rates["signal"] == sig)]
            v = float(sub["events_per_min"].sum()) if len(sub) else 0.0
            n = int(sub["n"].sum()) if len(sub) else 0
            add(rev, "pedal_throttle", metric, v, n_events=n)

        # ----- avcs -----
        sub = stutter_rates[(stutter_rates["rom_rev"] == rev)
                            & (stutter_rates["signal"] == "avcs_oscillation")]
        v = float(sub["events_per_min"].sum()) if len(sub) else 0.0
        n = int(sub["n"].sum()) if len(sub) else 0
        add(rev, "avcs", "avcs_osc_per_min", v, n_events=n)

        # ----- timing_sum (BTC + KCA·IAM analyzed jointly) -----
        kr = knock_rates[knock_rates["rom_rev"] == rev]
        if len(kr):
            add(rev, "timing_sum", "fbkc_events_per_min",
                float(kr["fbkc_events_per_min"].iloc[0]),
                n_events=int(kr["fbkc_events"].iloc[0]) if pd.notna(kr["fbkc_events"].iloc[0]) else 0)
            add(rev, "timing_sum", "flkc_events_per_min",
                float(kr["flkc_events_per_min"].iloc[0]),
                n_events=int(kr["flkc_events"].iloc[0]) if pd.notna(kr["flkc_events"].iloc[0]) else 0)
            add(rev, "timing_sum", "total_knock_per_min",
                float(kr["total_knock_events_per_min"].iloc[0]))
            add(rev, "timing_sum", "min_fbkc_depth",
                float(kr["min_fbkc"].iloc[0]) if pd.notna(kr["min_fbkc"].iloc[0]) else float("nan"))
        sub = stutter_rates[(stutter_rates["rom_rev"] == rev)
                            & (stutter_rates["signal"] == "timing_osc")]
        v = float(sub["events_per_min"].sum()) if len(sub) else 0.0
        n = int(sub["n"].sum()) if len(sub) else 0
        add(rev, "timing_sum", "timing_osc_per_min", v, n_events=n)

        # ----- wgdc -----
        pr = ramps_rev[ramps_rev["rom_rev"] == rev]
        if len(pr):
            add(rev, "wgdc", "mean_target_attainment",
                float(pr["mean_target_attainment"].iloc[0]),
                n_pulls=int(pr["n_pulls"].iloc[0]))
            add(rev, "wgdc", "mean_peak_mrp",
                float(pr["mean_peak_mrp"].iloc[0]),
                n_pulls=int(pr["n_pulls"].iloc[0]))
            add(rev, "wgdc", "wgdc_pegged_pulls",
                int(pr["wgdc_pegged"].iloc[0]),
                n_pulls=int(pr["n_pulls"].iloc[0]))

        # ----- ol_fueling -----
        for sig, metric in [
            ("afr_osc",             "afr_osc_per_min"),
            ("ffb_wbo2_divergence", "ffb_wbo2_div_per_min"),
        ]:
            sub = stutter_rates[(stutter_rates["rom_rev"] == rev)
                                & (stutter_rates["signal"] == sig)]
            v = float(sub["events_per_min"].sum()) if len(sub) else 0.0
            n = int(sub["n"].sum()) if len(sub) else 0
            add(rev, "ol_fueling", metric, v, n_events=n)
        mr = maf_rev[maf_rev["rom_rev"] == rev]
        if len(mr):
            add(rev, "ol_fueling", "maf_corr_mean_pct",
                float(mr["maf_corr_mean"].iloc[0]),
                n_samples=int(mr["maf_samples"].iloc[0]))
            add(rev, "ol_fueling", "maf_corr_mean_abs_pct",
                float(mr["maf_corr_mean_abs"].iloc[0]),
                n_samples=int(mr["maf_samples"].iloc[0]))

        # ----- cross_thread -----
        ss = stutter_sig[stutter_sig["rom_rev"] == rev]
        if len(ss):
            add(rev, "cross_thread", "stutter_signature_per_min",
                float(ss["events_per_min"].iloc[0]),
                n_events=int(ss["n"].iloc[0]))

    sc = pd.DataFrame(rows)
    return sc


def add_deltas(sc: pd.DataFrame, baseline: str) -> pd.DataFrame:
    """Add delta_vs_baseline and delta_vs_prior columns, per (thread, metric)."""
    sc = sc.copy()
    sc["delta_vs_baseline"] = np.nan
    sc["delta_vs_prior"] = np.nan

    for (thread, metric), g in sc.groupby(["thread", "metric"], sort=False):
        g_sorted = g.assign(_k=_rev_sort_key(g["rom_rev"])) \
                    .sort_values("_k").reset_index()
        base_val = float("nan")
        if baseline in g_sorted["rom_rev"].values:
            base_val = g_sorted.loc[
                g_sorted["rom_rev"] == baseline, "value"].iloc[0]
        prior_val = float("nan")
        for _, row in g_sorted.iterrows():
            idx = row["index"]
            v = row["value"]
            if pd.notna(base_val) and pd.notna(v):
                sc.loc[idx, "delta_vs_baseline"] = v - base_val
            if pd.notna(prior_val) and pd.notna(v):
                sc.loc[idx, "delta_vs_prior"] = v - prior_val
            prior_val = v
    return sc


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help=f"Baseline rom_rev (default: {DEFAULT_BASELINE})")
    ap.add_argument("--recompute-durations", action="store_true",
                    help="Bust the log_durations.csv cache")
    ap.add_argument("--output", default=str(TRENDS_DIR / "scorecard.csv"))
    args = ap.parse_args()

    # ---- inputs
    # Force rom_rev to string everywhere. Otherwise pandas auto-parses revs
    # like "20.10" as float 20.1, silently breaking joins. (Real bug found
    # in trends/pull_ramps.csv where "20.10" became 20.1.)
    rev_dtype = {"rom_rev": str}
    rev_map_raw = pd.read_csv(LOGS_DIR / "rom_rev_map.csv", dtype=rev_dtype)
    rev_map = _normalized_rev_map(rev_map_raw)
    stutter = pd.read_csv(TRENDS_DIR / "stutter_events.csv", dtype=rev_dtype)
    knock = pd.read_csv(TRENDS_DIR / "knock_by_cell.csv", dtype=rev_dtype)
    ramps = pd.read_csv(TRENDS_DIR / "pull_ramps.csv", dtype=rev_dtype)
    maf = pd.read_csv(TRENDS_DIR / "maf_corr_by_mafcell.csv", dtype=rev_dtype)

    durations = compute_log_durations(
        rev_map_raw, TRENDS_DIR / "log_durations.csv",
        recompute=args.recompute_durations,
    )

    # ---- per-thread metric extractors
    stutter_rates = m_stutter_rates(stutter, durations, rev_map)
    stutter_sig = m_stutter_signature(stutter, durations, rev_map)
    knock_rates = m_knock_rates(knock, durations, rev_map)
    ramps_rev = m_pull_ramps_rev(ramps)
    maf_rev = m_maf_corr_mean(maf)

    # ---- assemble + deltas
    sc = assemble_scorecard(stutter_rates, stutter_sig, knock_rates,
                            ramps_rev, maf_rev)
    sc = add_deltas(sc, args.baseline)

    # ---- run metadata
    run_ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sc.insert(0, "run_ts", run_ts)
    sc.insert(1, "baseline", args.baseline)

    # ---- write append-only + latest snapshot
    out_path = Path(args.output)
    latest = out_path.with_name(out_path.stem + "_latest.csv")
    if out_path.exists():
        existing = pd.read_csv(out_path)
        combined = pd.concat([existing, sc], ignore_index=True)
    else:
        combined = sc
    combined.to_csv(out_path, index=False)
    sc.to_csv(latest, index=False)

    # ---- print compact view
    print(f"Scorecard run {run_ts} — baseline={args.baseline}")
    print(f"Output: {out_path}")
    print(f"Latest snapshot: {latest}")
    print()
    print("=== Per-rev values (rows: thread/metric, cols: rom_rev) ===")
    view = sc.pivot_table(index=["thread", "metric"], columns="rom_rev",
                          values="value", aggfunc="first")
    rev_cols = [r for r in REV_ORDER if r in view.columns]
    view = view[rev_cols]
    print(view.round(3).to_string())

    if len(rev_cols):
        active = rev_cols[-1]
        print()
        print(f"=== Δ vs baseline ({args.baseline}) and Δ vs prior — active rev: {active} ===")
        active_view = sc[sc["rom_rev"] == active][
            ["thread", "metric", "value", "delta_vs_baseline", "delta_vs_prior"]
        ].sort_values(["thread", "metric"])
        print(active_view.round(3).to_string(index=False))


if __name__ == "__main__":
    main()
