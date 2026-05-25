"""
Dean asked: where am I seeing wbo2 20+ AFR — is it actually during CL/OL=7?

Plan:
1. Per event, show CL/OL state at the peak wbo2 sample and across the surrounding window.
2. Show wbo2 distribution across the whole log binned by CL/OL state.
3. Identify samples where wbo2 hits 20+ AND show CL/OL there.
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
dt = 1.0 / hz

# All samples with wbo2 >= 20: when do they happen, what CL/OL?
sat_mask = d["wbo2"] >= 20
print(f"=== All samples with wbo2 >= 20 AFR ({sat_mask.sum()} samples = {100*sat_mask.sum()/len(d):.1f}%) ===")
print(f"By CL/OL state:")
sat_by_cl = d.loc[sat_mask, "CL/OL"].value_counts().sort_index()
for v, n in sat_by_cl.items():
    print(f"  CL/OL={v:>4}: {n:>6}  ({100*n/sat_mask.sum():.1f}% of all wbo2>=20 samples)")

# By time bucket too
print(f"\nBy 60s bucket:")
d["bucket_60s"] = (d["t_rel_s"] // 60).astype(int)
sat_buckets = d.loc[sat_mask].groupby("bucket_60s").size()
for b, n in sat_buckets.items():
    t_start = b * 60
    print(f"  bucket {b} ({t_start}-{t_start+60}s): {n} sat samples")

# Per event from the earlier run, show CL/OL state explicitly
event_times = [104.68, 249.56, 254.96, 272.16, 279.20, 298.40, 313.64]
print("\n=== Per-event CL/OL state and wbo2/AFR at peak ===")
for et in event_times:
    # Find the sample closest to event start, then look in a +/- 1s window
    near = d[(d["t_rel_s"] >= et) & (d["t_rel_s"] <= et + 1.5)].copy()
    if len(near) == 0: continue
    # Sample with max wbo2 in that window
    peak = near.loc[near["wbo2"].idxmax()]
    cl_dist = near["CL/OL"].value_counts().sort_index().to_dict()
    print(f"\nEvent t={et}s:")
    print(f"  Surrounding 1.5s window CL/OL distribution: {cl_dist}")
    print(f"  Peak wbo2 sample: t={peak['t_rel_s']:.2f}s, CL/OL={peak['CL/OL']}, wbo2={peak['wbo2']:.2f}, AFR={peak['AFR']:.2f}, FFB={peak['FFB']:.2f}, RPM={peak['RPM']:.0f}, Throttle={peak['Throttle']:.1f}%, MAF={peak['MAF']:.1f} g/s, MAFV={peak['MAF(V)']:.3f}V, mrp={peak['mrp']:.2f} psi")

# Histogram of wbo2 readings overall (when valid)
print(f"\n=== wbo2 reading distribution by CL/OL ===")
for cl in [7, 8, 10]:
    sub = d[d["CL/OL"] == cl]["wbo2"]
    print(f"\nCL/OL={cl} ({len(sub)} samples):")
    print(f"  min: {sub.min():.2f}, p1: {sub.quantile(0.01):.2f}, p25: {sub.quantile(0.25):.2f}, median: {sub.median():.2f}")
    print(f"  p75: {sub.quantile(0.75):.2f}, p95: {sub.quantile(0.95):.2f}, p99: {sub.quantile(0.99):.2f}, max: {sub.max():.2f}")
    print(f"  fraction >= 20: {(sub >= 20).mean()*100:.1f}%")
    print(f"  fraction >= 16: {(sub >= 16).mean()*100:.1f}%")
