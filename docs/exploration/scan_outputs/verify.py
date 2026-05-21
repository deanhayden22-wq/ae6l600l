"""Re-derive key numbers from raw CSVs (not parquet) to confirm no parquet/dtype shenanigans."""
import pandas as pd, numpy as np
from pathlib import Path

# 1. Verify: lean residual at 1.0-1.3 load CL=8 on 20.12, computed from raw 5-17/log0002+log0007 (the two big logs)
print("=== Raw verify: 20.12 lean residual at 1.0-1.3 load CL=8 ===")
LOGS_20_12 = [
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0002.csv",
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0003.csv",
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0004.csv",
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0005.csv",
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0006.csv",
    "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-17 20.12/log0007.csv",
]
totals = []
for p in LOGS_20_12:
    d = pd.read_csv(p)
    d["wbo2_lag"] = d.wbo2.shift(-4)
    m = (d.wbo2_lag > 8) & (d.wbo2_lag < 22) & (d.FFB > 8) & (d.FFB < 18) & (d["CL/OL"]==8) & (d.load > 1.0) & (d.load < 1.3) & (d.MPH > 10)
    s = d[m]
    if len(s)==0: continue
    totals.append((Path(p).name, len(s), float((s.wbo2_lag - s.FFB).mean())))
all_s = pd.concat([pd.read_csv(p).assign(wbo2_lag=lambda x: x.wbo2.shift(-4)) for p in LOGS_20_12])
m = (all_s.wbo2_lag > 8) & (all_s.wbo2_lag < 22) & (all_s.FFB > 8) & (all_s.FFB < 18) & (all_s["CL/OL"]==8) & (all_s.load > 1.0) & (all_s.load < 1.3) & (all_s.MPH > 10)
agg = all_s[m]
print(f"\nAcross all 20.12 logs:  n={len(agg):,}  mean_resid={(agg.wbo2_lag - agg.FFB).mean():.3f}  median_resid={(agg.wbo2_lag - agg.FFB).median():.3f}")
for name, n, r in totals:
    print(f"  {name}: n={n:>5,}  mean_resid={r:.3f}")

# 2. Verify: stutter on 20.11 5-8 (the early 20.11 log) — should have highest /pedal-mod-min rate
print("\n=== Raw verify: stutter on 20.11 5-8 ===")
d = pd.read_csv("/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-8 20.11/5-8.csv")
d["dthr"] = d.Throttle.diff()
d["dapp"] = d.Accelerator.diff()
d["app_lag"] = d.Accelerator.shift(1)
d["app_3s_std"] = d.Accelerator.rolling(75, min_periods=10).std()
m = (d.Accelerator > 5) & (d.app_lag > 5) & (d.dapp.abs() < 1.5) & (d.dthr <= -3) & (d.RPM > 1500)
n = m.sum()
pedal_min = ((d.Accelerator > 5) & (d.app_3s_std > 5) & (d.RPM > 1500) & (d.RPM < 4500) & (d.load > 0.3) & (d.load < 1.5) & (d.MPH > 15) & (d.MPH < 65)).sum() / 25 / 60
print(f"5-8.csv (20.11 first log): n_stutters_raw={n}, pedal-mod-min in envelope={pedal_min:.2f}, rate={n/pedal_min if pedal_min>0 else 0:.2f}/min")

# 3. Confirm: FFB target across revs at load=1.0-1.3 is stable (no target change explaining residuals)
print("\n=== FFB target stability across revs at 1.0-1.3 load ===")
for rev_logs, rev in [
    (["/sessions/epic-happy-cannon/mnt/ae6l600l/logs/April/4-27 20.10/4-27.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-2/5-2.csv"], "20.10"),
    (["/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-8 20.11/5-8.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-10 20.11/log0003.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-11 20.11/log0001.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-11 20.11/log0002.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-11 20.11/log0003.csv",
      "/sessions/epic-happy-cannon/mnt/ae6l600l/logs/5-12 20.11/5-12.csv"], "20.11"),
    (LOGS_20_12, "20.12")]:
    parts = [pd.read_csv(p) for p in rev_logs]
    big = pd.concat(parts)
    sub = big[(big["CL/OL"]==8) & (big.load > 1.0) & (big.load < 1.3) & (big.FFB > 8) & (big.FFB < 18) & (big.MPH > 10)]
    print(f"  rev {rev}: FFB median={sub.FFB.median():.3f}  mean={sub.FFB.mean():.3f}  n={len(sub):,}")
