"""DEFEND: is the 0.49 AFR lean residual at 1.0-1.3 load on 20.12 a real shift or an artifact?
Concerns:
  1. Lag-correction: I used +8 samples (320ms). Validate with cross-correlation.
  2. CL=8 only? My orig included all states — but FFB is the *target* not the trim. Check.
  3. Maybe the load distribution shifted into a regime where stock FFB is leaner.
"""
import pandas as pd, numpy as np
from pathlib import Path

OUT = Path("/sessions/epic-happy-cannon/mnt/outputs/explore")
df = pd.read_parquet(OUT / "all.parquet").sort_values(["log_id","sample"]).reset_index(drop=True)

# 1. Lag check: cross-correlate FFB and wbo2 over a long segment (cruise on 20.12)
sub = df[(df.rev=="20.12") & (df["CL/OL"]==10) & (df.load > 0.8) & (df.load < 1.5) & (df.MPH > 30)].copy()
print(f"Sample for lag check: n={len(sub):,}")
# detrend
ffb = sub.FFB.values - sub.FFB.mean()
wb  = sub.wbo2.values - sub.wbo2.mean()
n = min(len(ffb), 20000)   # speed
ffb, wb = ffb[:n], wb[:n]
# cross-correlation at lags 0..30 samples
lags = np.arange(0, 30)
corrs = []
for L in lags:
    if L==0:
        c = np.corrcoef(ffb, wb)[0,1]
    else:
        c = np.corrcoef(ffb[:-L], wb[L:])[0,1]
    corrs.append(c)
import json
print("FFB-vs-wbo2 cross-correlation per lag (samples @25Hz, 40ms/sample):")
for L, c in zip(lags, corrs):
    if c > 0.4:
        print(f"  lag={L:2d} ({L*40} ms)  r={c:.3f} {'<-- peak' if c==max(corrs) else ''}")
best_lag = lags[np.argmax(corrs)]
print(f"\nBest lag = {best_lag} samples ({best_lag*40} ms). Memory said 320ms (8 samples).")

# 2. Re-run residual analysis with best lag, separately for CL=8 (closed loop) vs CL=10 (open loop, rich)
print("\n=== Residuals by CL state and load band, using best lag ===")
df["wbo2_aligned"] = df.groupby("log_id")["wbo2"].shift(-best_lag)
wkx = df[(df.wbo2_aligned > 8) & (df.wbo2_aligned < 22) & (df.FFB > 8) & (df.FFB < 18) & (df.MPH > 10)].copy()
wkx["resid"] = wkx.wbo2_aligned - wkx.FFB
wkx["load_band"] = pd.cut(wkx.load, [-1,0.5,0.8,1.0,1.3,1.6,3.0], labels=["<0.5","0.5-0.8","0.8-1.0","1.0-1.3","1.3-1.6",">1.6"])
g = wkx.groupby(["rev","CL/OL","load_band"], observed=True).resid.agg(["mean","median","std","count"]).reset_index()
g = g[g["count"] > 500]
g.columns = ["rev","CL/OL","load_band","resid_mean","resid_med","resid_std","n"]
print(g.to_string(index=False))
g.to_csv(OUT/"wb_residuals_defended.csv", index=False)

# 3. Check that FFB target values look similar across revs at same load — i.e. ROM target didn't change
print("\n=== Commanded FFB target by load band per rev (sanity check that target didn't move) ===")
ffb_g = wkx.groupby(["rev","load_band"], observed=True).FFB.agg(["mean","median","count"]).reset_index()
ffb_g = ffb_g[ffb_g["count"] > 500]
print(ffb_g.to_string(index=False))
