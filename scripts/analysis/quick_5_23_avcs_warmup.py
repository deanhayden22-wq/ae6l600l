"""
Time-evolution of AVCS oscillation during the cold drive (log0002).
Test: does AVCS settle as engine warms? Tells us cold-mechanism is real
without needing to resolve the table-axis dispute.

We don't have ECT logged, so we use:
  - IAT trend as a (very loose) cold proxy
  - Time since start (best proxy: engine internals warm continuously)
  - AVCS oscillation metric over time
"""
from pathlib import Path
import pandas as pd
import numpy as np

p = Path("logs/5-23 20.14/log0002.csv")
d = pd.read_csv(p)
for c in d.columns:
    d[c] = pd.to_numeric(d[c], errors="coerce")

# normalize time -> seconds since log start
d["t_rel_s"] = d["time"] - d["time"].min()

# focus on the steady-cruise band (22-30 mph, light throttle) — where the stutter shows
m = d["MPH"].between(22, 30) & d["Throttle"].between(2, 25)
cruise = d.loc[m].copy()
print(f"steady cruise samples (22-30 mph, 2-25% throttle): {len(cruise):,}")
print(f"time span in cruise: {cruise['t_rel_s'].min():.0f}s -> {cruise['t_rel_s'].max():.0f}s")

# bucket by 60-sec windows of relative time
cruise["bucket"] = (cruise["t_rel_s"] // 60).astype(int)
agg = cruise.groupby("bucket").agg(
    n=("RPM","size"),
    t_mid_s=("t_rel_s","mean"),
    IAT_mean=("IAT","mean"),
    mph_mean=("MPH","mean"),
    avcs_mean=("avcs","mean"),
    avcs_std=("avcs","std"),
    avcs_range=("avcs", lambda x: x.max()-x.min()),
    avcs_jump_count_3=("avcs", lambda x: (x.diff().abs()>3).sum()),
    avcs_jump_count_5=("avcs", lambda x: (x.diff().abs()>5).sum()),
    avcs_pct_zero=("avcs", lambda x: (x==0).mean()*100),
)
print("\n## AVCS metrics by 60-sec bucket through cold drive:")
with pd.option_context("display.float_format","{:.2f}".format,"display.width",140):
    print(agg.to_string())

# Now do the same for log0001 (warm) -- contrast
print("\n\n## Same metrics on WARM drive (log0001) for contrast:")
w = pd.read_csv("logs/5-23 20.14/log0001.csv")
for c in w.columns: w[c] = pd.to_numeric(w[c], errors="coerce")
w["t_rel_s"] = w["time"] - w["time"].min()
mw = w["MPH"].between(22, 30) & w["Throttle"].between(2, 25)
cruise_w = w.loc[mw].copy()
print(f"warm steady cruise samples: {len(cruise_w):,}")
cruise_w["bucket"] = (cruise_w["t_rel_s"] // 60).astype(int)
agg_w = cruise_w.groupby("bucket").agg(
    n=("RPM","size"),
    t_mid_s=("t_rel_s","mean"),
    IAT_mean=("IAT","mean"),
    avcs_std=("avcs","std"),
    avcs_range=("avcs", lambda x: x.max()-x.min()),
    avcs_jump_count_3=("avcs", lambda x: (x.diff().abs()>3).sum()),
    avcs_pct_zero=("avcs", lambda x: (x==0).mean()*100),
)
with pd.option_context("display.float_format","{:.2f}".format,"display.width",140):
    print(agg_w.to_string())
