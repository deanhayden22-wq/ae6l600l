"""
Quick overview of 5-25 20.15 log:
- duration / sample count / Hz
- identify the cold-wbo2 window (CL/OL=7 indicates startup; AFR=20.33 also signals
  invalid wbo2). Dean said he pulled away from the gas station before CL/OL=7
  finished and the wbo2 wasn't fully warm.
- find the cold/warmup window and propose a t_warm cutoff
- distribution of CL/OL states
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
dur_s = d["t_rel_s"].max()
hz = len(d) / dur_s
print(f"Samples: {len(d)}, duration: {dur_s:.1f}s = {dur_s/60:.2f} min, sample rate: {hz:.2f} Hz")

# CL/OL distribution
print(f"\nCL/OL distribution (samples / pct / minutes):")
cl_counts = d["CL/OL"].value_counts().sort_index()
for v, n in cl_counts.items():
    print(f"  CL/OL={v:>4}: {n:>6}  ({100*n/len(d):5.1f}%)  {n/hz/60:5.2f} min")

# wbo2 validity (AFR=20.33 means wbo2 not reading, invalid signal)
n_invalid = ((d["wbo2"] >= 20) | (d["wbo2"] <= 7)).sum()
print(f"\nwbo2 invalid samples (>=20 or <=7): {n_invalid} ({100*n_invalid/len(d):.1f}%)")

# When does CL/OL=7 happen?
cl7_mask = d["CL/OL"] == 7
if cl7_mask.any():
    cl7_first = d.loc[cl7_mask, "t_rel_s"].iloc[0]
    cl7_last = d.loc[cl7_mask, "t_rel_s"].iloc[-1]
    cl7_count = cl7_mask.sum()
    print(f"\nCL/OL=7 (startup cold-cat warmup): {cl7_count} samples, {cl7_first:.1f}s to {cl7_last:.1f}s")

# When does wbo2 become valid?
wbo2_valid = d["wbo2"].between(10, 19.5)
if wbo2_valid.any():
    first_valid = d.loc[wbo2_valid, "t_rel_s"].iloc[0]
    print(f"\nFirst valid wbo2 sample: t={first_valid:.1f}s")
    # also find when wbo2 is consistently valid (no long invalid stretches)
    rolling_valid = wbo2_valid.rolling(int(5*hz), min_periods=1).mean()
    consistently_valid = rolling_valid > 0.95
    if consistently_valid.any():
        first_consistent = d.loc[consistently_valid, "t_rel_s"].iloc[0]
        print(f"First t with 5-second-rolling wbo2 valid >95%: {first_consistent:.1f}s")

# Snapshot of early samples
print(f"\nFirst 10 valid samples (t, CL/OL, wbo2, AFR, FFB, ECT?, RPM, MPH, Throttle):")
cols = ["t_rel_s", "CL/OL", "wbo2", "AFR", "FFB", "RPM", "MPH", "Throttle"]
print(d[cols].head(40).to_string(index=False))

# When did Dean leave (start moving)?
moving = d["MPH"] > 5
if moving.any():
    first_moving = d.loc[moving, "t_rel_s"].iloc[0]
    print(f"\nFirst sample with MPH > 5: t={first_moving:.1f}s")
    # MPH cumulative
print(f"\nMPH percentiles: 50%={d['MPH'].median():.1f}, 90%={d['MPH'].quantile(0.9):.1f}, max={d['MPH'].max():.1f}")

# coolant temp proxy via what columns we have... we only have IAT not ECT
print(f"\nIAT range: {d['IAT'].min():.1f}F to {d['IAT'].max():.1f}F (mean {d['IAT'].mean():.1f}F)")

# Knock summary
n_fbkc = (d["FBKC"] < 0).sum()
print(f"\nFBKC<0 samples: {n_fbkc}, deepest FBKC: {d['FBKC'].min():.2f}")
n_flkc = (d["FLKC"] < 0).sum()
print(f"FLKC<0 samples: {n_flkc}, deepest FLKC: {d['FLKC'].min():.2f}")
print(f"IAM range: {d['IAM'].min():.3f} to {d['IAM'].max():.3f}")

# Boost
wot = d["Throttle"] >= 85
print(f"\nThrottle >=85% samples: {wot.sum()}, peak mrp: {d.loc[wot, 'mrp'].max() if wot.any() else 'n/a'}")
print(f"Max mrp overall: {d['mrp'].max():.2f} psi")
