"""DRILL v2: real stutters only.
A real stutter = ECU cuts the throttle plate while driver is HOLDING pedal.
Filter: Accelerator > 5%, |dapp| < 1.5, dthr <= -3, RPM > 1500.
Additionally require pedal was stable for the prior 3 samples too.
"""
import pandas as pd, numpy as np
from pathlib import Path

OUT = Path("/sessions/epic-happy-cannon/mnt/outputs/explore")
df = pd.read_parquet(OUT / "all.parquet").sort_values(["log_id","sample"]).reset_index(drop=True)

df["dthr"] = df.groupby("log_id")["Throttle"].diff()
df["dapp"] = df.groupby("log_id")["Accelerator"].diff()
df["app_3s_std"] = df.groupby("log_id")["Accelerator"].rolling(75, min_periods=10).std().reset_index(level=0, drop=True)
df["app_lag"] = df.groupby("log_id")["Accelerator"].shift(1)

# Real stutter: pedal actively applied, pedal not in transit, throttle drops
mask = (
    (df.Accelerator > 5) &              # pedal applied
    (df.app_lag > 5) &                  # was applied prior sample too
    (df.dapp.abs() < 1.5) &             # pedal essentially stable sample-to-sample
    (df.dthr <= -3) &                   # throttle plate drops ≥3%
    (df.RPM > 1500)
)
stut = df[mask].copy()
print(f"Stutters after refinement: {len(stut):,}")
for rev in ["20.10","20.11","20.12"]:
    s = stut[stut.rev==rev]
    drv_min = df[(df.rev==rev)&(df.MPH>5)&(df.Accelerator>5)].pipe(lambda x: len(x))/25/60   # "pedal-applied driving minutes"
    rate = len(s) / drv_min if drv_min>0 else 0
    print(f"  rev {rev}: {len(s)} events,  pedal-on-min={drv_min:.1f},  rate={rate:.3f}/min")

# Now look at fingerprints of refined stutters
stut["rpm_band"] = pd.cut(stut.RPM, [0,1500,2000,2500,3000,3500,4500,7000])
stut["load_band"] = pd.cut(stut.load, [0,0.4,0.7,1.0,1.3,1.6,3.0])
for rev in ["20.10","20.11","20.12"]:
    s = stut[stut.rev==rev]
    if len(s)==0: continue
    print(f"\nrev {rev} RPM×load distribution (n={len(s)}):")
    print(pd.crosstab(s.rpm_band, s.load_band, dropna=False))

# Compare mechanism fingerprints
print("\n--- Mechanism fingerprints (refined) ---")
df["dRQTQ"] = df.groupby("log_id")["RQTQ"].diff()
df["dTrgt"] = df.groupby("log_id")["Trgt_Boost"].diff()
df["dTdp"] = df.groupby("log_id")["Tdp"].diff()
stut = df[mask].copy()
for rev in ["20.10","20.11","20.12"]:
    s = stut[stut.rev==rev]
    if len(s)==0: continue
    cmd_down = ((s.dTrgt < -0.3)).mean()*100
    rqtq_cut = ((s.dRQTQ < -5)).mean()*100
    rqtq_big_cut = ((s.dRQTQ < -30)).mean()*100
    overshoot = ((s.mrp - s.Trgt_Boost) > 0.5).mean()*100
    tdp_down = ((s.dTdp < -0.3)).mean()*100
    in_boost = (s.mrp > 2).mean()*100
    print(f"rev {rev}: cmd_target_down={cmd_down:5.1f}% RQTQ_cut={rqtq_cut:5.1f}% RQTQ_huge_cut={rqtq_big_cut:5.1f}% boost_overshoot={overshoot:5.1f}% Tdp_drop={tdp_down:5.1f}% in_boost={in_boost:5.1f}%")

# look at 10 deepest from refined set
print("\n--- 10 deepest REFINED 20.12 stutters with windows ---")
deepest = stut[stut.rev=="20.12"].nsmallest(10, "dthr")
for _, ev in deepest.iterrows():
    idx = ev.name
    window = df.loc[max(0,idx-5):idx+5, ["log_id","sample","RPM","Accelerator","Throttle","RQTQ","load","mrp","Trgt_Boost","Tdp","FBKC","Timing","avcs","CL/OL"]].copy()
    print(f"\n[{ev.log_id} sample={int(ev['sample'])}] dthr={ev.dthr:.2f}% APP={ev.Accelerator:.1f} RPM={ev.RPM:.0f} load={ev.load:.2f} mrp={ev.mrp:.1f}")
    print(window.to_string(index=False))

# Save refined per-log table
rows = []
for log_id, sub in df.groupby("log_id"):
    drv_min = ((sub.MPH > 5) & (sub.Accelerator > 5)).sum() / 25 / 60
    n_stut = mask.loc[sub.index].sum()
    rate = n_stut / drv_min if drv_min > 0 else 0
    rows.append({"log_id": log_id, "rev": sub.rev.iloc[0], "pedal_on_min": round(drv_min,1), "n_stutters": int(n_stut), "per_min": round(rate,3)})
pd.DataFrame(rows).sort_values(["rev","log_id"]).to_csv(OUT/"stutter_refined_per_log.csv", index=False)
print("\nSaved stutter_refined_per_log.csv")
