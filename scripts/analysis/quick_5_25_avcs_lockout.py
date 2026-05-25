"""
Confirm Dean's diagnosis: AVCS was locked out across the whole 5-25 drive.
Compare actual avcs vs what the cruise/non-cruise table would have commanded,
and against the 20.14 baseline distribution.
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

# Overall avcs distribution
print("=== 20.15 5-25 log AVCS distribution ===")
print(f"min: {d['avcs'].min():.1f}°, p25: {d['avcs'].quantile(0.25):.1f}°, median: {d['avcs'].median():.1f}°")
print(f"p75: {d['avcs'].quantile(0.75):.1f}°, p95: {d['avcs'].quantile(0.95):.1f}°, max: {d['avcs'].max():.1f}°")
print(f"fraction at 0°: {(d['avcs']==0).mean()*100:.1f}%")
print(f"fraction <= 5°: {(d['avcs']<=5).mean()*100:.1f}%")
print(f"fraction <= 10°: {(d['avcs']<=10).mean()*100:.1f}%")
print(f"fraction >= 15°: {(d['avcs']>=15).mean()*100:.1f}%")
print(f"fraction >= 20°: {(d['avcs']>=20).mean()*100:.1f}%")

# AVCS by RPM band - it should rise with RPM and load
print(f"\nAVCS by RPM band (full log):")
d["rpm_bin"] = pd.cut(d["RPM"], [0, 1500, 2000, 2500, 3000, 3500, 4000, 5000, 7000])
g = d.groupby("rpm_bin", observed=True).agg(
    n=("avcs", "size"),
    avcs_p50=("avcs", "median"),
    avcs_p95=("avcs", lambda x: x.quantile(0.95)),
    avcs_max=("avcs", "max"),
    load_mean=("load", "mean"),
)
print(g.round(2).to_string())

# Compare against the 20.14 log0003 baseline
p14 = Path("logs/5-23 20.14/log0003.csv")
d14 = pd.read_csv(p14)
for c in d14.columns:
    d14[c] = pd.to_numeric(d14[c], errors="coerce")
d14 = d14.sort_values("sample").reset_index(drop=True)
print(f"\n=== 20.14 5-23 log0003 AVCS distribution (baseline, working AVCS) ===")
print(f"min: {d14['avcs'].min():.1f}°, p25: {d14['avcs'].quantile(0.25):.1f}°, median: {d14['avcs'].median():.1f}°")
print(f"p75: {d14['avcs'].quantile(0.75):.1f}°, p95: {d14['avcs'].quantile(0.95):.1f}°, max: {d14['avcs'].max():.1f}°")
print(f"fraction >= 15°: {(d14['avcs']>=15).mean()*100:.1f}%")
print(f"fraction >= 20°: {(d14['avcs']>=20).mean()*100:.1f}%")

print(f"\n20.14 AVCS by RPM band (apples-to-apples):")
d14["rpm_bin"] = pd.cut(d14["RPM"], [0, 1500, 2000, 2500, 3000, 3500, 4000, 5000, 7000])
g14 = d14.groupby("rpm_bin", observed=True).agg(
    n=("avcs", "size"),
    avcs_p50=("avcs", "median"),
    avcs_p95=("avcs", lambda x: x.quantile(0.95)),
    avcs_max=("avcs", "max"),
    load_mean=("load", "mean"),
)
print(g14.round(2).to_string())

# WOT pull comparison — event 3 in 20.15 was 4304 RPM WOT, AVCS 8° max
# 20.14 WOT comparable
wot15 = d[d["Throttle"] >= 90]
wot14 = d14[d14["Throttle"] >= 90]
print(f"\n=== AVCS during WOT (Throttle >= 90%) ===")
print(f"20.15: n={len(wot15)}, avcs median={wot15['avcs'].median():.1f}°, max={wot15['avcs'].max():.1f}°, peak RPM at max avcs sample: {wot15.loc[wot15['avcs'].idxmax(), 'RPM']:.0f} (if any)")
print(f"20.14: n={len(wot14)}, avcs median={wot14['avcs'].median():.1f}°, max={wot14['avcs'].max():.1f}°")
