"""
Log review ingestion: load one log CSV, compute per-metric trends rows,
append to scripts/analysis/trends/*.csv.

Per SOP scripts/analysis/log_review_checklist.md. Schemas in trends/README.md.

Usage:
    python log_review_ingest.py --log <path> --date YYYY-MM-DD --rom <rom_rev>
    python log_review_ingest.py --map logs/rom_rev_map.csv --all

Idempotent on (log_date, rom_rev, log_path) key.
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

# verified from 20.10 .bin OL B Low table
RPM_BREAKPOINTS = np.array([800, 1200, 1600, 1900, 2200, 2600, 3000, 3300,
                            3700, 4000, 4400, 4800, 5200, 5500, 6000, 6300,
                            6600, 7000], dtype=float)
LOAD_BREAKPOINTS = np.array([0.27, 0.57, 0.73, 1.0, 1.17, 1.36, 1.51, 1.64,
                             1.78, 1.95, 2.12, 2.28, 2.44, 2.6, 2.9, 3.22,
                             3.7], dtype=float)

_maf_csv = TRENDS_DIR / "maf_scaling_breakpoints.csv"
_maf_df = pd.read_csv(_maf_csv)
MAF_V_BREAKPOINTS = _maf_df["V"].to_numpy(dtype=float)
MAF_GS_BREAKPOINTS = _maf_df["g_s"].to_numpy(dtype=float)

MRP_BIN = 0.5
# SAMPLES_PER_SEC and WIN_1S are now per-log; defaults below.
DEFAULT_SAMPLES_PER_SEC = 25

# Map old RomRaider full-name logger columns to current short names.
OLD_TO_NEW_COLUMNS = {
    "Time": "time",
    "A/F Correction #1 (%)": "AFC",
    "A/F Learning #1 (%)": "AFL",
    "A/F Sensor #1 (AFR)": "AFR",
    "A/F Sensor #1 Resistance (ohm)": "EGT",
    "Atmospheric Pressure (psi)": "ATM(psi)",
    "CL/OL Fueling* (status)": "CL/OL",
    "Engine Load (Calculated) (g/rev)": "load",
    "Engine Speed (rpm)": "RPM",
    "Feedback Knock Correction (1-byte)** (degrees)": "FBKC",
    "Feedback Knock Correction (4-byte) (degrees)": "FBKC",
    "Final Fueling Base (2-byte)* (estimated AFR)": "FFB",
    "Fine Learning Knock Correction (degrees)": "FLKC",
    "IAM (multiplier)": "IAM",
    "Ignition Total Timing (degrees)": "Timing",
    "Injector Duty Cycle (%)": "IDC",
    "Intake Air Temperature (F)": "IAT",
    "Intake VVT Advance Angle Left (degrees)": "avcs",
    "Manifold Relative Pressure (Corrected) (psi)": "mrp",
    "Mass Airflow (g/s)": "MAF",
    "Mass Airflow Sensor Voltage (V)": "MAF(V)",
    "Primary Wastegate Duty Cycle (%)": "wgdc",
    "Requested Torque* (raw ecu value)": "RQTQ",
    "Target Boost Relative (4-byte)* (psi relative)": "Trgt_Boost",
    "Throttle Opening Angle (%)": "Throttle",
    "Turbo Dynamics Integral (4-byte)* (absolute %)": "tdi",
    "Turbo Dynamics Proportional (4-byte)* (absolute %)": "Tdp",
    "Vehicle Speed (mph)": "MPH",
    "PLX O2 - Wideband (AFR Gasoline)": "wbo2",
    "Accelerator Pedal Angle (%)": "Accelerator",
}


def _parse_time_str(s):
    """Parse 'MM:SS.t', 'HH:MM:SS.t', or 'H:MM:SS AM/PM' to seconds.
    Numeric strings pass through. Returns NaN on parse failure."""
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    # Strip AM/PM, remember it for 12h offset
    pm = False
    am = False
    upper = s.upper()
    if upper.endswith("AM"):
        am = True
        s = s[:-2].strip()
    elif upper.endswith("PM"):
        pm = True
        s = s[:-2].strip()
    if ":" not in s:
        try:
            return float(s)
        except Exception:
            return float("nan")
    parts = s.split(":")
    try:
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        if len(parts) == 3:
            h = int(parts[0])
            if pm and h < 12:
                h += 12
            elif am and h == 12:
                h = 0
            return h * 3600 + int(parts[1]) * 60 + float(parts[2])
    except Exception:
        return float("nan")
    return float("nan")


def detect_sample_rate(time_arr):
    """Return samples per second.
    Heuristic, robust to: fractional-second time (5-2 style 0.04s),
    integer-second time (3-21 style, multiple samples per second),
    and stitched sessions where time resets mid-log (3-30 style).

    Rule:
    1. If median diff is sub-second positive: rate = round(1/median_diff)
       — this is correct for any millisecond-resolution log regardless of
       session breaks (median is robust to discontinuities).
    2. If median diff is integer-second (>=1s): rate = median samples per
       integer-second bucket — use this for old integer-time logs.
    3. Default 25 if neither applies."""
    arr = np.asarray(time_arr, dtype=float)
    arr = arr[np.isfinite(arr)]
    if len(arr) < 2:
        return 25
    diffs = np.diff(arr)
    pos = diffs[(diffs > 0) & (diffs < 60)]
    if len(pos) > 0:
        median_dt = float(np.median(pos))
        if 0 < median_dt < 1:
            return max(int(round(1.0 / median_dt)), 1)
    # Fall back to integer-second bucket count
    sec = np.floor(arr).astype(int)
    _, counts = np.unique(sec, return_counts=True)
    if len(counts) == 0:
        return 25
    rate = int(round(np.median(counts)))
    return rate if rate > 0 else 25



def nearest_bin(values: np.ndarray, breakpoints: np.ndarray) -> np.ndarray:
    idx = np.searchsorted(breakpoints, values)
    idx = np.clip(idx, 1, len(breakpoints) - 1)
    left = breakpoints[idx - 1]
    right = breakpoints[idx]
    pick_left = (values - left) <= (right - values)
    return np.where(pick_left, left, right)


def load_log(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    # Translate old RomRaider full-name columns -> short names
    rename = {k: v for k, v in OLD_TO_NEW_COLUMNS.items() if k in df.columns}
    if rename:
        df = df.rename(columns=rename)
    for col in ("AFR", "KNOCK_FLAG"):
        if col not in df.columns:
            df[col] = np.nan
    # Parse non-numeric time first
    if "time" in df.columns:
        if df["time"].dtype == object:
            df["time"] = df["time"].apply(_parse_time_str)
    numeric_cols = [
        "wbo2", "AFR", "FFB", "EGT", "AFC", "AFL", "correction", "RPM",
        "load", "MPH", "Timing", "IAT", "MAF", "MAF(V)", "Accelerator",
        "Throttle", "RQTQ", "ATM(psi)", "MAP", "mrp", "Trgt_Boost", "IAM",
        "CL/OL", "FLKC", "FBKC", "avcs", "wgdc", "tdi", "Tdp", "IPW", "IDC",
        "KNOCK_FLAG",
    ]
    for c in numeric_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    # Augment formulas (only if missing)
    if "load" not in df.columns:
        df["load"] = df["MAF"] * 60 / df["RPM"]
    if "mrp" not in df.columns and "MAP" in df.columns and "ATM(psi)" in df.columns:
        df["mrp"] = df["MAP"] - df["ATM(psi)"]
    if "IDC" not in df.columns and "IPW" in df.columns:
        df["IDC"] = df["IPW"] * df["RPM"] / 1200
    if "correction" not in df.columns:
        clol = df["CL/OL"]
        cl = (clol == 8)
        ol_with_o2 = (clol == 10)
        corr = np.full(len(df), np.nan)
        corr[cl] = (df.loc[cl, "AFC"] + df.loc[cl, "AFL"]).to_numpy()
        if df["AFR"].notna().any():
            mask = ol_with_o2 & df["AFR"].notna() & (df["wbo2"] > 0)
            corr[mask] = ((1 - df.loc[mask, "AFR"] / df.loc[mask, "wbo2"]) * 100).to_numpy()
        df["correction"] = corr
    # Old logs may lack Accelerator: fall back to Throttle for the "engine being driven" proxy.
    if "Accelerator" not in df.columns:
        df["Accelerator"] = df["Throttle"]
    return df


def compute_knock_by_cell(df, log_date, rom_rev, log_path):
    fbkc = df["FBKC"].to_numpy()
    flkc = df["FLKC"].to_numpy()
    rpm = df["RPM"].to_numpy()
    load = df["load"].to_numpy()
    fbkc_neg = fbkc < 0
    flkc_decr = np.zeros_like(fbkc, dtype=bool)
    flkc_decr[1:] = flkc[1:] < flkc[:-1]
    # event = each FBKC deepening (more negative than prior sample). NaN-safe.
    edge_fbkc = np.zeros_like(fbkc, dtype=bool)
    edge_fbkc[1:] = (fbkc[1:] < fbkc[:-1]) & np.isfinite(fbkc[1:]) & np.isfinite(fbkc[:-1])
    edge_flkc = flkc_decr.copy()
    rpm_bin = nearest_bin(rpm, RPM_BREAKPOINTS)
    load_bin = nearest_bin(load, LOAD_BREAKPOINTS)
    work = pd.DataFrame({
        "rpm_bin": rpm_bin, "load_bin": load_bin,
        "fbkc_neg": fbkc_neg.astype(int),
        "flkc_decr": flkc_decr.astype(int),
        "edge_fbkc": edge_fbkc.astype(int),
        "edge_flkc": edge_flkc.astype(int),
        "fbkc": fbkc,
    })
    mask = (work["fbkc_neg"] == 1) | (work["flkc_decr"] == 1)
    work = work[mask]
    if work.empty:
        return pd.DataFrame()
    g = work.groupby(["rpm_bin", "load_bin"])
    out = g.agg(
        sample_count_fbkc_neg=("fbkc_neg", "sum"),
        sample_count_flkc_decr=("flkc_decr", "sum"),
        event_count_fbkc=("edge_fbkc", "sum"),
        event_count_flkc=("edge_flkc", "sum"),
        mean_fbkc=("fbkc", lambda s: float(s[s < 0].mean()) if (s < 0).any() else np.nan),
        min_fbkc=("fbkc", "min"),
    ).reset_index()
    out.insert(0, "log_path", log_path)
    out.insert(0, "rom_rev", rom_rev)
    out.insert(0, "log_date", log_date)
    return out


def compute_wot_pulls(df, log_date, rom_rev, log_path, samples_per_sec=25):
    tps = df["Throttle"].to_numpy()
    in_wot = tps > 95.0
    diff = np.diff(in_wot.astype(int), prepend=0, append=0)
    starts = np.where(diff == 1)[0]
    ends = np.where(diff == -1)[0]
    win_1s = samples_per_sec
    runs = [(s, e) for s, e in zip(starts, ends) if (e - s) >= win_1s]
    merged = []
    for s, e in runs:
        if merged and (s - merged[-1][1]) < (samples_per_sec // 2):
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    rows = []
    fbkc_arr = df["FBKC"].to_numpy()
    flkc_arr = df["FLKC"].to_numpy()
    flkc_decr = np.concatenate([[False], flkc_arr[1:] < flkc_arr[:-1]])
    knock_mask = (fbkc_arr < 0) | flkc_decr
    for pid, (s, e) in enumerate(merged):
        seg = df.iloc[s:e]
        rows.append({
            "log_date": log_date, "rom_rev": rom_rev, "log_path": log_path,
            "pull_id": pid,
            "start_time": float(seg["time"].iloc[0]),
            "duration_s": (e - s) / samples_per_sec,
            "peak_rpm": float(seg["RPM"].max()),
            "peak_mrp_psi": float(seg["mrp"].max()),
            "peak_maf_gs": float(seg["MAF"].max()),
            "min_fbkc": float(seg["FBKC"].min()),
            "min_flkc": float(seg["FLKC"].min()),
            "knock_during": int(knock_mask[s:e].any()),
            "peak_wbo2": float(seg["wbo2"].max()),
            "mean_wbo2_minus_ffb": float((seg["wbo2"] - seg["FFB"]).mean()),
            "peak_wgdc": float(seg["wgdc"].max()),
            "iam_start": float(seg["IAM"].iloc[0]),
            "iam_end": float(seg["IAM"].iloc[-1]),
        })
    return pd.DataFrame(rows)


def compute_maf_corr(df, log_date, rom_rev, log_path):
    filt = (
        (df["FFB"] <= 14.7)
        & (df["correction"].abs() < 25)
        & (df["Accelerator"] > 2)
        & (df["CL/OL"] == 8)
    )
    sub = df.loc[filt, ["MAF(V)", "MAF", "correction"]].dropna()
    if sub.empty:
        return pd.DataFrame()
    mafv_bin = nearest_bin(sub["MAF(V)"].to_numpy(), MAF_V_BREAKPOINTS)
    mafgs_bin = nearest_bin(sub["MAF"].to_numpy(), MAF_GS_BREAKPOINTS)
    work = pd.DataFrame({
        "mafv_bin": mafv_bin, "mafgs_bin": mafgs_bin,
        "correction": sub["correction"].to_numpy(),
    })
    g = work.groupby(["mafv_bin", "mafgs_bin"])
    out = g.agg(
        sample_count=("correction", "size"),
        mean_correction=("correction", "mean"),
        median_correction=("correction", "median"),
        std_correction=("correction", "std"),
    ).reset_index()
    out.insert(0, "log_path", log_path)
    out.insert(0, "rom_rev", rom_rev)
    out.insert(0, "log_date", log_date)
    return out


def _rolling_std(arr, win):
    return pd.Series(arr).rolling(win, min_periods=win).std().to_numpy()


def _rolling_range(arr, win):
    s = pd.Series(arr)
    return (s.rolling(win, min_periods=win).max() - s.rolling(win, min_periods=win).min()).to_numpy()


def compute_stutter_events(df, log_date, rom_rev, log_path, samples_per_sec=25):
    win = samples_per_sec
    rpm = df["RPM"].to_numpy()
    load = df["load"].to_numpy()
    mrp = df["mrp"].to_numpy()
    app = df["Accelerator"].to_numpy()
    tps = df["Throttle"].to_numpy()
    avcs = df["avcs"].to_numpy()
    timing = df["Timing"].to_numpy()
    wbo2 = df["wbo2"].to_numpy()
    ffb = df["FFB"].to_numpy()
    t = df["time"].to_numpy()
    std_rpm = _rolling_std(rpm, win)
    std_load = _rolling_std(load, win)
    std_app = _rolling_std(app, win)
    std_tps = _rolling_std(tps, win)
    std_timing = _rolling_std(timing, win)
    std_wbo2 = _rolling_std(wbo2, win)
    rng_avcs = _rolling_range(avcs, win)
    rng_rpm = _rolling_range(rpm, win)
    LAG = 8
    afr_delta = np.full_like(wbo2, np.nan, dtype=float)
    afr_delta[:-LAG] = wbo2[LAG:] - ffb[:-LAG]
    std_afr_delta = _rolling_std(afr_delta, win)
    rows = []
    eid = [0]

    def emit(idx, signal, magnitude):
        rows.append({
            "log_date": log_date, "rom_rev": rom_rev, "log_path": log_path,
            "event_id": eid[0], "start_time": float(t[idx]),
            "duration_s": 1.0, "signal": signal,
            "magnitude": float(magnitude),
            "rpm_at_event": float(rpm[idx]),
            "load_at_event": float(load[idx]),
            "mrp_at_event": float(mrp[idx]),
            "accelerator_at_event": float(app[idx]),
            "throttle_at_event": float(tps[idx]),
            "avcs_at_event": float(avcs[idx]),
            "timing_at_event": float(timing[idx]),
            "notes": "",
        })
        eid[0] += 1

    cond = (std_app < 0.5) & (std_tps > 1.0)
    for i in np.where(cond)[0][::win]:
        emit(i, "throttle_hunt_at_steady_app", std_tps[i])
    cond = (rng_avcs >= 10.0) & (std_rpm < 50) & (std_load < 0.05)
    for i in np.where(cond)[0][::win]:
        emit(i, "avcs_oscillation", rng_avcs[i])
    cond = ((std_timing > 3.5) | (std_wbo2 > 1.0)) & (std_rpm < 50) \
           & (std_load < 0.05) & (std_tps < 1.0)
    for i in np.where(cond)[0][::win]:
        sig = "timing_osc" if std_timing[i] > 2.0 else "afr_osc"
        mag = std_timing[i] if sig == "timing_osc" else std_wbo2[i]
        emit(i, sig, mag)
    cond = (rng_rpm >= 400) & (std_tps < 1.0)
    for i in np.where(cond)[0][::win]:
        emit(i, "rpm_swing_steady_tps", rng_rpm[i])
    cond = (std_afr_delta > 1.0) & (std_tps < 1.0)
    for i in np.where(cond)[0][::win]:
        emit(i, "ffb_wbo2_divergence", std_afr_delta[i])

    return pd.DataFrame(rows)


def compute_ve_proxy(df, log_date, rom_rev, log_path, samples_per_sec=25):
    win = samples_per_sec
    std_rpm = _rolling_std(df["RPM"].to_numpy(), win)
    std_mrp = _rolling_std(df["mrp"].to_numpy(), win)
    std_tps = _rolling_std(df["Throttle"].to_numpy(), win)
    steady = (std_rpm < 50) & (std_mrp < 0.5) & (std_tps < 1.0)
    sub = df.loc[steady, ["RPM", "mrp", "MAF"]].dropna()
    if sub.empty:
        return pd.DataFrame()
    rpm_bin = nearest_bin(sub["RPM"].to_numpy(), RPM_BREAKPOINTS)
    mrp_bin = (np.round(sub["mrp"].to_numpy() / MRP_BIN) * MRP_BIN).round(2)
    work = pd.DataFrame({"rpm_bin": rpm_bin, "mrp_bin": mrp_bin,
                         "MAF": sub["MAF"].to_numpy()})
    g = work.groupby(["rpm_bin", "mrp_bin"])
    out = g.agg(
        sample_count=("MAF", "size"),
        mean_maf_gs=("MAF", "mean"),
        median_maf_gs=("MAF", "median"),
        std_maf_gs=("MAF", "std"),
    ).reset_index()
    out.insert(0, "log_path", log_path)
    out.insert(0, "rom_rev", rom_rev)
    out.insert(0, "log_date", log_date)
    return out


def append_idempotent(target, new_rows, key_cols):
    if new_rows is None or new_rows.empty:
        return 0
    if target.exists():
        existing = pd.read_csv(target, dtype={"rom_rev": str, "log_path": str, "log_date": str})
    else:
        existing = pd.DataFrame()
    # Force string types on key cols of new_rows too
    for kc in ("rom_rev", "log_path", "log_date"):
        if kc in new_rows.columns:
            new_rows[kc] = new_rows[kc].astype(str)
        if kc in existing.columns:
            existing[kc] = existing[kc].astype(str)
    if not existing.empty:
        keys = new_rows[key_cols].drop_duplicates()
        merged_keys = existing.merge(keys, on=key_cols, how="left", indicator=True)
        existing = existing[merged_keys["_merge"] == "left_only"]
    out = pd.concat([existing, new_rows], ignore_index=True)
    out.to_csv(target, index=False)
    return len(new_rows)


def ingest_one(log_path, log_date, rom_rev):
    log_path = log_path.resolve() if log_path.is_absolute() else (REPO_ROOT / log_path).resolve()
    df = load_log(log_path)
    rel_path = str(log_path.relative_to(REPO_ROOT)).replace("\\", "/")
    sps = detect_sample_rate(df["time"].to_numpy()) if "time" in df.columns else DEFAULT_SAMPLES_PER_SEC
    counts = {"_samples_per_sec": sps}
    counts["knock_by_cell"] = append_idempotent(
        TRENDS_DIR / "knock_by_cell.csv",
        compute_knock_by_cell(df, log_date, rom_rev, rel_path),
        ["log_date", "rom_rev", "log_path"])
    counts["wot_pulls"] = append_idempotent(
        TRENDS_DIR / "wot_pulls.csv",
        compute_wot_pulls(df, log_date, rom_rev, rel_path, samples_per_sec=sps),
        ["log_date", "rom_rev", "log_path"])
    counts["maf_corr_by_mafcell"] = append_idempotent(
        TRENDS_DIR / "maf_corr_by_mafcell.csv",
        compute_maf_corr(df, log_date, rom_rev, rel_path),
        ["log_date", "rom_rev", "log_path"])
    counts["stutter_events"] = append_idempotent(
        TRENDS_DIR / "stutter_events.csv",
        compute_stutter_events(df, log_date, rom_rev, rel_path, samples_per_sec=sps),
        ["log_date", "rom_rev", "log_path"])
    counts["ve_proxy"] = append_idempotent(
        TRENDS_DIR / "ve_proxy.csv",
        compute_ve_proxy(df, log_date, rom_rev, rel_path, samples_per_sec=sps),
        ["log_date", "rom_rev", "log_path"])
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", type=str)
    ap.add_argument("--date", type=str)
    ap.add_argument("--rom", type=str)
    ap.add_argument("--map", type=str)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    if args.all:
        if not args.map:
            print("--all requires --map", file=sys.stderr); sys.exit(2)
        m = pd.read_csv(args.map)
        for _, row in m.iterrows():
            log = LOGS_DIR / row["log_path"]
            if not log.exists():
                print(f"SKIP missing: {log}"); continue
            print(f"Ingesting {row['log_path']} (date={row['log_date']} rom={row['rom_rev']})")
            counts = ingest_one(log, row["log_date"], row["rom_rev"])
            print(f"  -> {counts}")
        # After --all, append a per-rev rollup to REVIEW_LOG.md
        try:
            from rev_comparison import compare, format_report
            revs = []
            for r in m["rom_rev"].astype(str):
                if r not in revs: revs.append(r)
            if len(revs) >= 2:
                report = "\n".join(format_report(compare(a, b)) for a, b in zip(revs[:-1], revs[1:]))
                review = REPO_ROOT / "logs" / "REVIEW_LOG.md"
                if review.exists():
                    text = review.read_text()
                else:
                    text = ""
                from datetime import datetime
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                section = f"\n## auto-generated rev rollup ({stamp})\n\n" + report + "\n"
                # Insert at top of newest-first section (after the marker line if present)
                marker = "<!-- Entries below this line, newest first -->"
                if marker in text:
                    text = text.replace(marker, marker + section, 1)
                else:
                    text += section
                review.write_text(text)
                print(f"  -> appended rev rollup to logs/REVIEW_LOG.md")
        except Exception as e:
            print(f"  -> rev rollup skipped: {e}")
    else:
        if not (args.log and args.date and args.rom):
            print("Provide --log --date --rom OR --map --all", file=sys.stderr); sys.exit(2)
        counts = ingest_one(Path(args.log), args.date, args.rom)
        print(counts)
        # If a rom_rev_map exists, find the rev that comes before this one and
        # append a single comparison block to REVIEW_LOG.md
        try:
            from rev_comparison import compare, format_report
            from datetime import datetime
            map_path = REPO_ROOT / "logs" / "rom_rev_map.csv"
            if map_path.exists():
                m = pd.read_csv(map_path).sort_values("log_date")
                revs = []
                for r in m["rom_rev"].astype(str):
                    if r not in revs: revs.append(r)
                rev = str(args.rom)
                if rev in revs:
                    i = revs.index(rev)
                    if i > 0:
                        prev = revs[i-1]
                        report = format_report(compare(prev, rev))
                        review = REPO_ROOT / "logs" / "REVIEW_LOG.md"
                        text = review.read_text() if review.exists() else ""
                        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                        section = f"\n## ingest {args.date} (rev {rev}) auto-rollup ({stamp})\n\n" + report + "\n"
                        marker = "<!-- Entries below this line, newest first -->"
                        if marker in text:
                            text = text.replace(marker, marker + section, 1)
                        else:
                            text += section
                        review.write_text(text)
                        print("  -> appended rev rollup to logs/REVIEW_LOG.md")
        except Exception as e:
            print(f"  -> rev rollup skipped: {e}")


if __name__ == "__main__":
    main()
