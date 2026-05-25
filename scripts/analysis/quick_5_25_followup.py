"""
Follow-up on 20.15 gate concerns:
1. Are the 7 lean events real tip-in stabs, or constant-throttle lean spikes
   (different mechanism, e.g. AVCS sweep)?
2. AFC drift over the warm window — is it actually -3.4%, or is wbo2 still
   stabilizing? Show AFC binned by time and by RPM/load cell.
3. Compute per-OL-minute event rate as a cross-check on G1.
4. Recompute 20.14's events/OL-min for an apples-to-apples comparison.
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
hz = len(d) / d["t_rel_s"].max()
dt = 1.0/hz

trip_A = d["t_rel_s"].between(60.0, 361.0)
trip_B = d["t_rel_s"].between(660.0, 723.0)
warm = trip_A | trip_B

d["throttle_d_per_sample"] = d["Throttle"].diff()
d["throttle_d_3"] = d["Throttle"].diff().rolling(3, min_periods=1).sum()
d["lean"] = d["wbo2"] - d["FFB"]
d["BE"] = d["Trgt_Boost"] - d["mrp"]

# Re-find the 7 events and dump full context for each
in_window = warm & (d["RPM"] > 1200) & (d["CL/OL"] == 10) & (d["Throttle"] > 8) \
            & (d["wbo2"].between(13, 19.5)) & (d["FFB"].between(10, 16))
event_mask = in_window & (d["lean"] >= 2.0) & (d["throttle_d_3"] > 1.5)
arr = event_mask.to_numpy()
runs = []
i = 0
while i < len(arr):
    if arr[i]:
        j = i
        while j < len(arr) and arr[j]:
            j += 1
        if j - i >= 2: runs.append((i, j-1))
        i = j
    else:
        i += 1

print("=== Full context per event (20.15 warm window) ===\n")
for k, (a, b) in enumerate(runs, start=1):
    a2 = max(0, a-int(1*hz)); b2 = min(len(d)-1, b+int(1*hz))
    seg = d.iloc[a2:b2+1]
    sample0 = d.iloc[a]
    sample_peak = seg.loc[seg["wbo2"].idxmax()]
    print(f"Event #{k} at t={sample0['t_rel_s']:.2f}s, RPM {sample0['RPM']:.0f}, load {sample0['load']:.2f}")
    print(f"  throttle: {sample0['Throttle']:.1f}% -> peak {seg['Throttle'].max():.1f}%, max d/sample {seg['throttle_d_per_sample'].max():.2f}%, max d_3 {seg['throttle_d_3'].max():.2f}%")
    print(f"  wbo2:    {sample0['wbo2']:.2f} -> peak {sample_peak['wbo2']:.2f}  (FFB at peak {sample_peak['FFB']:.2f}, lean {sample_peak['wbo2'] - sample_peak['FFB']:.2f})")
    print(f"  mrp:     {sample0['mrp']:.2f} -> peak {seg['mrp'].max():.2f} psi, BE at start {sample0['BE']:.2f} psi")
    print(f"  avcs:    {sample0['avcs']:.1f}° -> swing {seg['avcs'].max() - seg['avcs'].min():.1f}° (min {seg['avcs'].min():.1f}, max {seg['avcs'].max():.1f})")
    print(f"  duration: {(b-a+1)*dt*1000:.0f} ms")
    print()

# ---- AFC drift over the warm window ----
print("=== AFC drift across warm window (CL/OL=8, RPM>=1200) ===")
d["throttle_d_smooth"] = d["Throttle"].diff().rolling(int(2*hz), min_periods=1).sum().abs()
cruise_mask = warm & (d["CL/OL"] == 8) & (d["RPM"] >= 1200) & (d["throttle_d_smooth"] < 1.0) & (d["MPH"] > 15)
print(f"Total cruise samples: {cruise_mask.sum()}")
d_cr = d[cruise_mask].copy()
d_cr["bucket_60s"] = (d_cr["t_rel_s"] // 60).astype(int)
print(d_cr.groupby("bucket_60s").agg(
    n=("AFC", "size"),
    afc_mean=("AFC", "mean"),
    afc_median=("AFC", "median"),
    afl_mean=("AFL", "mean"),
    corr_mean=("correction", "mean"),
    wbo2_mean=("wbo2", "mean"),
    afr_mean=("AFR", "mean"),
    mph_mean=("MPH", "mean"),
    rpm_mean=("RPM", "mean"),
    load_mean=("load", "mean"),
).round(2).to_string())

# ---- AFC by load cell (any throttle change tolerated) ----
print("\n=== AFC by (RPM, load) cell in warm CL/OL=8 (no throttle filter) ===")
cl8_mask = warm & (d["CL/OL"] == 8) & (d["RPM"] >= 1200) & (d["MPH"] > 15)
d_cl8 = d[cl8_mask].copy()
d_cl8["rpm_bin"] = pd.cut(d_cl8["RPM"], [1200, 1900, 2400, 2900, 3400, 4000, 5000])
d_cl8["load_bin"] = pd.cut(d_cl8["load"], [0, 0.5, 0.8, 1.2, 1.6, 2.0, 3.0])
g = d_cl8.groupby(["rpm_bin", "load_bin"], observed=True).agg(
    n=("AFC", "size"),
    afc_mean=("AFC", "mean"),
).reset_index()
g = g[g["n"] >= 20].sort_values("n", ascending=False)
print(g.head(20).to_string(index=False))

# ---- Compare to 20.14: events/OL-min ----
p14 = Path("logs/5-23 20.14/log0003.csv")
d14 = pd.read_csv(p14)
for c in d14.columns:
    d14[c] = pd.to_numeric(d14[c], errors="coerce")
d14 = d14.sort_values("sample").reset_index(drop=True)
d14["t_rel_s"] = d14["time"] - d14["time"].min()
hz14 = len(d14) / d14["t_rel_s"].max()
dt14 = 1.0/hz14
d14["throttle_d_3"] = d14["Throttle"].diff().rolling(3, min_periods=1).sum()
d14["lean"] = d14["wbo2"] - d14["FFB"]
ol14_mask = (d14["RPM"] > 1200) & (d14["CL/OL"] == 10) & (d14["Throttle"] > 8) \
            & (d14["wbo2"].between(13, 19.5)) & (d14["FFB"].between(10, 16))
ol14_min = ol14_mask.sum() * dt14 / 60
evt14_mask = ol14_mask & (d14["lean"] >= 2.0) & (d14["throttle_d_3"] > 1.5)
arr14 = evt14_mask.to_numpy()
runs14 = []
i = 0
while i < len(arr14):
    if arr14[i]:
        j = i
        while j < len(arr14) and arr14[j]: j += 1
        if j-i >= 2: runs14.append((i, j-1))
        i = j
    else:
        i += 1
print(f"\n=== 20.14 log0003 baseline (recomputed for apples-to-apples) ===")
print(f"Drive: {d14['t_rel_s'].max()/60:.1f} min, {hz14:.2f} Hz")
print(f"OL-exposure: {ol14_min:.2f} min ({100*ol14_mask.sum()/len(d14):.1f}% of drive)")
print(f"Events: {len(runs14)}")
print(f"Events/total-min: {len(runs14) / (d14['t_rel_s'].max()/60):.3f}")
print(f"Events/OL-min:    {len(runs14) / ol14_min:.3f}")

# 20.15
warm_dur_min = warm.sum() * dt / 60
in_window_full = warm & (d["RPM"] > 1200) & (d["CL/OL"] == 10) & (d["Throttle"] > 8) \
                 & (d["wbo2"].between(13, 19.5)) & (d["FFB"].between(10, 16))
ol15_min = in_window_full.sum() * dt / 60
print(f"\n=== 20.15 warm window ===")
print(f"Warm dur: {warm_dur_min:.2f} min")
print(f"OL-exposure (warm): {ol15_min:.2f} min ({100*in_window_full.sum()/warm.sum():.1f}% of warm)")
print(f"Events: {len(runs)}")
print(f"Events/warm-min:  {len(runs) / warm_dur_min:.3f}")
print(f"Events/OL-min:    {len(runs) / ol15_min:.3f}")
