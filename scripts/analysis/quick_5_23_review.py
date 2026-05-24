"""
First-pass review of 5-23 20.14 drive -- answer two questions:
  1. AFR going lean on acceleration?
  2. Cold 25-mph stutter (log0002 = cold drive)?

Uses standard 34-col schema. Writes a markdown summary to stdout.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

LOGS = [
    Path("logs/5-23 20.14/log0001.csv"),  # warm
    Path("logs/5-23 20.14/log0002.csv"),  # cold
]
LABELS = {"log0001.csv": "warm", "log0002.csv": "cold"}

# Target AFR -- use FFB as ECU's commanded fueling target proxy
# wbo2 is the actual AFR. lean ratio = wbo2 / target. >1 = lean.

def load(p: Path) -> pd.DataFrame:
    df = pd.read_csv(p)
    df["label"] = LABELS[p.name]
    df["src"] = p.name
    # numeric coercion
    for c in df.columns:
        if c in ("label", "src"):
            continue
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

def summarize_overall(df: pd.DataFrame, label: str) -> None:
    # time column is in SECONDS (25 Hz sampling)
    dur_s = df["time"].max() - df["time"].min()
    print(f"\n## Overall -- {label} ({len(df):,} samples)")
    print(f"- duration: {dur_s:.0f}s ({dur_s/60:.1f} min)")
    print(f"- RPM range: {df['RPM'].min():.0f} - {df['RPM'].max():.0f}, "
          f"median {df['RPM'].median():.0f}")
    print(f"- MPH range: {df['MPH'].min():.0f} - {df['MPH'].max():.0f}")
    print(f"- IAT start -> end: {df['IAT'].iloc[0]:.1f} -> {df['IAT'].iloc[-1]:.1f} F")
    print(f"- throttle peak: {df['Throttle'].max():.1f}%, APP peak: {df['Accelerator'].max():.1f}%")
    print(f"- mrp peak: {df['mrp'].max():.2f} psi, MAP peak: {df['MAP'].max():.2f} psi")
    print(f"- knock: FBKC samples<0: {(df['FBKC']<0).sum()}, "
          f"min FBKC {df['FBKC'].min():.2f} deg, "
          f"FLKC samples<0: {(df['FLKC']<0).sum()}, min FLKC {df['FLKC'].min():.2f} deg")
    cl = (df["CL/OL"] == 8).mean() * 100
    ol = (df["CL/OL"] == 10).mean() * 100
    print(f"- CL/OL: CL={cl:.1f}%, OL={ol:.1f}%")


def afr_lean_overview(df: pd.DataFrame, label: str) -> None:
    """Histogram-style summary of wbo2 vs FFB."""
    # only meaningful when wbo2 is in sensor range AND engine running (RPM>500)
    m = (df["RPM"] > 500) & (df["wbo2"].between(10, 22)) & (df["FFB"].between(10, 22))
    d = df.loc[m].copy()
    d["lean_pct"] = (d["wbo2"] - d["FFB"]) / d["FFB"] * 100.0
    print(f"\n## wbo2 vs FFB (target) -- {label}")
    print(f"- samples scored: {len(d):,} of {len(df):,}")
    print(f"- mean wbo2 - FFB lean%: {d['lean_pct'].mean():+.2f}%")
    print(f"- lean events (wbo2 >= FFB + 1.0 AFR): {(d['wbo2'] - d['FFB'] >= 1.0).sum():,}  "
          f"({(d['wbo2'] - d['FFB'] >= 1.0).mean()*100:.2f}% of samples)")
    print(f"- big lean (wbo2 >= FFB + 2.0 AFR): {(d['wbo2'] - d['FFB'] >= 2.0).sum():,}  "
          f"({(d['wbo2'] - d['FFB'] >= 2.0).mean()*100:.2f}% of samples)")
    print(f"- peak wbo2 (excluding overrun): "
          f"{d.loc[d['Throttle']>5, 'wbo2'].max():.2f}")


def accel_events(df: pd.DataFrame, label: str) -> pd.DataFrame:
    """
    Identify acceleration events: throttle steps from <8% to >=15% AND RPM rising,
    sustained for at least 0.5s. Per-event lean stats.
    time column is in seconds.
    """
    df = df.sort_values("sample").reset_index(drop=True)
    th = df["Throttle"].to_numpy()
    rpm = df["RPM"].to_numpy()
    t = df["time"].to_numpy()  # seconds

    in_event = False
    start = -1
    events = []
    for i in range(1, len(df)):
        if not in_event:
            if th[i] >= 15.0 and th[i-1] < 8.0:
                in_event = True
                start = i
        else:
            ended = (th[i] < 5.0) or (i == len(df)-1)
            if ended:
                end = i
                if t[end] - t[start] >= 0.5:  # >=0.5s
                    seg = df.iloc[start:end+1]
                    target = seg["FFB"].clip(lower=10, upper=22)
                    wb = seg["wbo2"].clip(lower=10, upper=22)
                    lean = (wb - target)
                    events.append({
                        "label": label,
                        "src": seg["src"].iloc[0],
                        "t_start_s": float(t[start]),
                        "dur_s": float(t[end]-t[start]),
                        "rpm_min": seg["RPM"].min(),
                        "rpm_max": seg["RPM"].max(),
                        "mph_min": seg["MPH"].min(),
                        "mph_max": seg["MPH"].max(),
                        "throttle_peak": seg["Throttle"].max(),
                        "app_peak": seg["Accelerator"].max(),
                        "mrp_peak": seg["mrp"].max(),
                        "load_peak": seg["load"].max(),
                        "wbo2_peak_lean": wb.max(),
                        "lean_peak_afr": lean.max(),
                        "lean_at_peak_throttle": lean.loc[seg["Throttle"].idxmax()],
                        "afc_min": seg["AFC"].min(),
                        "afc_max": seg["AFC"].max(),
                        "afl": seg["AFL"].iloc[-1],
                        "ol_pct": (seg["CL/OL"] == 10).mean()*100,
                        "min_fbkc": seg["FBKC"].min(),
                        "n_samples": len(seg),
                    })
                in_event = False
                start = -1
    e = pd.DataFrame(events)
    return e


def cold_25mph_band(df: pd.DataFrame) -> None:
    """For cold drive, look at 22-28 mph cruise and AVCS hunting."""
    m = df["MPH"].between(22, 28) & (df["Throttle"].between(2, 25))
    d = df.loc[m].copy()
    if len(d) == 0:
        print("\n## Cold 25-mph band: NO samples in 22-28 mph / 2-25% throttle")
        return
    print(f"\n## Cold 25-mph band (22-28 mph, 2-25% throttle): {len(d):,} samples")
    print(f"- RPM in band: {d['RPM'].min():.0f}-{d['RPM'].max():.0f}, "
          f"median {d['RPM'].median():.0f}")
    print(f"- load median: {d['load'].median():.3f}, "
          f"P95 {d['load'].quantile(0.95):.3f}")
    print(f"- AVCS range (max-min): {d['avcs'].max()-d['avcs'].min():.1f} deg, "
          f"AVCS std {d['avcs'].std():.2f} deg")
    # AVCS deltas sample-to-sample
    avcs_jump = d["avcs"].diff().abs()
    print(f"- AVCS sample-to-sample |d|: mean {avcs_jump.mean():.2f} deg, "
          f"max {avcs_jump.max():.1f} deg, "
          f"|d|>3 deg count {(avcs_jump>3).sum()}, "
          f"|d|>5 deg count {(avcs_jump>5).sum()}")
    # focus on the 0.20-load column at 2800-3000 RPM (the durable stutter cell)
    sub = d[(d["RPM"].between(2700, 3100)) & (d["load"].between(0.15, 0.30))]
    print(f"\n  ### Within the 0.20-load x 2800-3000 RPM cell: {len(sub):,} samples")
    if len(sub) > 5:
        print(f"  - AVCS std: {sub['avcs'].std():.2f} deg, "
              f"range {sub['avcs'].max()-sub['avcs'].min():.1f} deg, "
              f"|d|>3 deg {(sub['avcs'].diff().abs()>3).sum()}")
        print(f"  - timing std: {sub['Timing'].std():.2f} deg, "
              f"timing min {sub['Timing'].min():.1f} deg")
        # Lean in this cell
        lean = sub["wbo2"] - sub["FFB"]
        print(f"  - wbo2 - FFB: mean {lean.mean():+.2f}, max {lean.max():+.2f}")
        print(f"  - knock samples (FBKC<0): {(sub['FBKC']<0).sum()}, "
              f"min FBKC {sub['FBKC'].min():.2f} deg")

    # also dump the absolute count of "stutter-like" timing/AVCS rapid events
    rapid = (d["avcs"].diff().abs() > 5).rolling(50).sum().max()
    print(f"\n- worst 50-sample window of |dAVCS|>5: {int(rapid) if pd.notna(rapid) else 0}")


def main():
    dfs = {p.name: load(p) for p in LOGS}
    for name, df in dfs.items():
        summarize_overall(df, f"{LABELS[name]} ({name})")

    for name, df in dfs.items():
        afr_lean_overview(df, f"{LABELS[name]} ({name})")

    # Acceleration events table -- combined
    all_events = pd.concat(
        [accel_events(df, LABELS[name]) for name, df in dfs.items()],
        ignore_index=True,
    )
    print(f"\n## Acceleration events (throttle <8% -> >=15%, >=0.5s)")
    print(f"- total events: {len(all_events)}")
    if len(all_events):
        # show worst-lean ones
        worst = all_events.sort_values("lean_peak_afr", ascending=False).head(12)
        cols = ["label","src","t_start_s","dur_s","rpm_min","rpm_max",
                "mph_min","mph_max","throttle_peak","mrp_peak",
                "lean_peak_afr","lean_at_peak_throttle","afc_min","afc_max","ol_pct","min_fbkc"]
        with pd.option_context("display.max_columns", None,
                               "display.width", 200,
                               "display.float_format", "{:.2f}".format):
            print("\n  ### Top 12 events by peak lean (wbo2 - FFB):")
            print(worst[cols].to_string(index=False))
        # by label aggregates
        print("\n  ### Aggregates by drive:")
        agg = all_events.groupby("label").agg(
            n=("dur_s","size"),
            mean_peak_lean=("lean_peak_afr","mean"),
            max_peak_lean=("lean_peak_afr","max"),
            mean_afc_min=("afc_min","mean"),
            mean_mrp_peak=("mrp_peak","mean"),
            min_fbkc=("min_fbkc","min"),
        )
        print(agg.to_string())

    # Cold-specific 25 mph band
    cold = dfs["log0002.csv"]
    cold_25mph_band(cold)
    # compare warm same band
    print("\n--- WARM (log0001) same band for comparison ---")
    cold_25mph_band(dfs["log0001.csv"])


if __name__ == "__main__":
    main()
