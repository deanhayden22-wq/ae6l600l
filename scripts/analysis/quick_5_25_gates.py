"""
Score 20.15 vs the five pre-drive gates from open-issues.md, with the
cold-warmup windows excluded (Dean drove off the second cold restart at
the gas station before CL/OL=7 ended).

Log structure (from quick_5_25_warmup.py):
  Trip A: 0-361s    (cold start at home + drive to gas station)
  GAP:    361-569s  (logger stopped while pumping)
  Trip B: 569-723s  (cold restart at gas station; CL/OL=7 active 569-603s; wbo2 not fully warm till ~660s)

Warm windows (use these to score gates):
  A:   60-361s   (after initial CL/OL=7 ended at ~36s + 24s wbo2 settle)
  B:   660-723s  (after the gas-station CL/OL=7 ended + wbo2 settled)

Gates:
  G1: tip-in shortfall events/min  (target < 0.8 from 1.10 baseline on 20.14)
  G2: median lean peak AFR         (target < 6.0 from 7.22)
  G3: BE coverage shift            (target >40% of lean events with BE >= 5 psi)
  G4: transition-cusp knock samples (target < 200 in 2600-3700 x 1.0-1.17)
  G5: CL steady cruise AFC mean    (target +/- 1.5%; baseline +0.93%)
"""
from pathlib import Path
import numpy as np
import pandas as pd

p = Path("logs/5-25 20.15/log0001.csv")
d = pd.read_csv(p)
for c in d.columns:
    d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["t_rel_s"] = d["time"] - d["time"].min()

# Hz from data, not nominal
hz = len(d) / d["t_rel_s"].max()
dt = 1.0 / hz
print(f"Log: {len(d)} samples, {d['t_rel_s'].max():.1f}s, {hz:.2f} Hz, dt={dt*1000:.1f}ms")

# Warm-window mask
trip_A = d["t_rel_s"].between(60.0, 361.0)
trip_B = d["t_rel_s"].between(660.0, 723.0)
warm = trip_A | trip_B
warm_dur_s = warm.sum() * dt
warm_dur_min = warm_dur_s / 60
print(f"Warm window samples: {warm.sum()}, dur: {warm_dur_s:.1f}s = {warm_dur_min:.2f} min")
print(f"  Trip A (60-361s):  {trip_A.sum()} samples")
print(f"  Trip B (660-723s): {trip_B.sum()} samples")

# Sanity: CL/OL distribution in warm window
print(f"\nWarm-window CL/OL distribution:")
cl_counts = d.loc[warm, "CL/OL"].value_counts().sort_index()
for v, n in cl_counts.items():
    print(f"  CL/OL={v:>4}: {n:>6} ({100*n/warm.sum():5.1f}%)")

# --------------------------------------------------------------------------
# G1 + G2 + G3: tip-in lean-event sweep on the WARM WINDOW, OL only
# --------------------------------------------------------------------------
d["throttle_d_per_sample"] = d["Throttle"].diff()
d["throttle_d_3"] = d["Throttle"].diff().rolling(3, min_periods=1).sum()
d["lean"] = d["wbo2"] - d["FFB"]
d["BE"] = d["Trgt_Boost"] - d["mrp"]

# Mask: warm, real throttle activity, in OL, wbo2 + FFB valid
in_window = (
    warm
    & (d["RPM"] > 1200)
    & (d["CL/OL"] == 10)
    & (d["Throttle"] > 8)
    & (d["wbo2"].between(13, 19.5))
    & (d["FFB"].between(10, 16))
)

# OL exposure minutes in the warm window (event rate denominator)
ol_exposure_min = in_window.sum() * dt / 60
print(f"\nOL-exposure minutes in warm window: {ol_exposure_min:.2f}")

# A "lean event" sample: lean >= 2.0 AFR AND throttle just opened
event_mask = in_window & (d["lean"] >= 2.0) & (d["throttle_d_3"] > 1.5)

# Find contiguous runs >= 2 samples (~100ms+)
arr = event_mask.to_numpy()
runs = []
i = 0
while i < len(arr):
    if arr[i]:
        j = i
        while j < len(arr) and arr[j]:
            j += 1
        if j - i >= 2:
            runs.append((i, j-1))
        i = j
    else:
        i += 1

# Per-event stats
events = []
for (a, b) in runs:
    a2 = max(0, a-5); b2 = min(len(d)-1, b+5)
    seg = d.iloc[a2:b2+1]
    sample0 = d.iloc[a]
    events.append({
        "t_start_s": float(sample0["t_rel_s"]),
        "dur_s": (b - a + 1) * dt,
        "rpm_at_start": float(sample0["RPM"]),
        "throttle_start": float(sample0["Throttle"]),
        "throttle_peak": float(seg["Throttle"].max()),
        "throttle_step": float(seg["Throttle"].max() - sample0["Throttle"]),
        "throttle_d_per_sample_max": float(seg["throttle_d_per_sample"].max()),
        "throttle_d_3_max": float(seg["throttle_d_3"].max()),
        "mrp_peak": float(seg["mrp"].max()),
        "BE_at_event": float(sample0["BE"]),
        "BE_peak": float(seg["BE"].max()),
        "lean_peak": float(seg["lean"].max()),
        "wbo2_peak": float(seg["wbo2"].max()),
        "ffb_at_peak": float(seg.loc[seg["wbo2"].idxmax(), "FFB"]),
    })
ev = pd.DataFrame(events)
print(f"\n=== G1+G2+G3 tip-in lean event sweep ===")
print(f"Events found: {len(ev)}")
if len(ev) > 0:
    g1_rate = len(ev) / warm_dur_min if warm_dur_min > 0 else float("nan")
    g1_rate_ol = len(ev) / ol_exposure_min if ol_exposure_min > 0 else float("nan")
    print(f"G1 events/min (over warm dur): {g1_rate:.3f}  (target < 0.8; 20.14 was 1.10)")
    print(f"G1 events/OL-min:              {g1_rate_ol:.3f}  (denominator is OL exposure only)")
    print(f"G2 median lean peak: {ev['lean_peak'].median():.2f} AFR  (target < 6.0; 20.14 was 7.22)")
    print(f"   p25={ev['lean_peak'].quantile(0.25):.2f}, p75={ev['lean_peak'].quantile(0.75):.2f}, max={ev['lean_peak'].max():.2f}")
    # G3 BE coverage shift
    n_above5 = (ev["BE_at_event"] >= 5).sum()
    n_total = len(ev)
    pct_above5 = 100 * n_above5 / n_total
    print(f"G3 events w/ BE >= 5 psi at start: {n_above5}/{n_total} = {pct_above5:.1f}%  (target >40%; 20.14 was 26%)")
    print(f"   BE-at-event median: {ev['BE_at_event'].median():.2f}, p25 {ev['BE_at_event'].quantile(0.25):.2f}, p75 {ev['BE_at_event'].quantile(0.75):.2f}")
    print(f"\nTop 5 worst lean events in warm window:")
    top = ev.sort_values("lean_peak", ascending=False).head(5)
    with pd.option_context("display.float_format", "{:.2f}".format, "display.width", 200):
        print(top[["t_start_s","rpm_at_start","throttle_start","throttle_peak","BE_at_event","lean_peak","wbo2_peak","ffb_at_peak"]].to_string(index=False))
else:
    print("(no events in warm window)")

# --------------------------------------------------------------------------
# G4: transition-cusp knock samples (2600-3700 RPM x 1.0-1.17 load) — full log
#     (need to apply shift filter for fair compare). 20.14 baseline: 304 raw,
#     447 real after filter; cluster cell threshold target < 200.
# --------------------------------------------------------------------------
# Use full log including warm AND cold (knock just needs to fire, but cold-cat
# CL/OL=7 should not be firing knock anyway; check)
fbkc_neg = d["FBKC"] < 0
print(f"\n=== G4 transition-cusp knock ===")
print(f"Total FBKC<0 samples (full log): {fbkc_neg.sum()}")
print(f"In CL/OL=7 (cold-cat): {(fbkc_neg & (d['CL/OL'] == 7)).sum()}")
print(f"In CL/OL=8 (closed-loop): {(fbkc_neg & (d['CL/OL'] == 8)).sum()}")
print(f"In CL/OL=10 (open-loop): {(fbkc_neg & (d['CL/OL'] == 10)).sum()}")
cluster_mask = d["RPM"].between(2600, 3700) & d["load"].between(1.0, 1.17)
n_cluster = (fbkc_neg & cluster_mask).sum()
print(f"FBKC<0 in transition-cusp cluster 2600-3700 x 1.0-1.17: {n_cluster}  (target < 200; 20.14 baseline 304 raw, 447 real after filter)")
print(f"Deepest FBKC: {d['FBKC'].min():.2f}")
print(f"FLKC<0 samples: {(d['FLKC'] < 0).sum()}, deepest: {d['FLKC'].min():.2f}")
print(f"IAM range: {d['IAM'].min():.3f} to {d['IAM'].max():.3f}")

# --------------------------------------------------------------------------
# G5: cruise regression check - CL steady-cruise AFC mean
# --------------------------------------------------------------------------
# Filter: throttle_d ~= 0 (cruise), CL/OL=8, RPM >= 1200
d["throttle_d_smooth"] = d["Throttle"].diff().rolling(int(2*hz), min_periods=1).sum().abs()
cruise_mask = (
    warm
    & (d["CL/OL"] == 8)
    & (d["RPM"] >= 1200)
    & (d["throttle_d_smooth"] < 1.0)  # rolling 2s throttle change small
    & (d["MPH"] > 15)
)
print(f"\n=== G5 CL steady-cruise AFC mean ===")
print(f"Cruise-filter samples in warm window: {cruise_mask.sum()} ({cruise_mask.sum()*dt:.1f}s)")
if cruise_mask.sum() > 0:
    afc_mean = d.loc[cruise_mask, "AFC"].mean()
    afc_median = d.loc[cruise_mask, "AFC"].median()
    afl_mean = d.loc[cruise_mask, "AFL"].mean()
    correction_mean = d.loc[cruise_mask, "correction"].mean()
    print(f"AFC mean:   {afc_mean:+.2f}%  (target +/- 1.5%; 20.14 was +0.93%)")
    print(f"AFC median: {afc_median:+.2f}%")
    print(f"AFL mean:   {afl_mean:+.2f}%")
    print(f"correction mean: {correction_mean:+.2f}%  (CL/OL=8: AFC+AFL active trims)")

# Quick context: any sustained boost / WOT in warm window?
wot_warm = warm & (d["Throttle"] >= 85)
print(f"\nWOT (>=85% throttle) samples in warm: {wot_warm.sum()}")
print(f"Max mrp in warm: {d.loc[warm, 'mrp'].max():.2f} psi")
