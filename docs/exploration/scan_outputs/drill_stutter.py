"""DRILL: characterize ECU-commanded throttle drops (stutters) where pedal is held steady.
Filter: dthr ≤ -3% in one sample, |dapp| < 1%, RPM > 1500.
Questions:
  - WHERE in the operating envelope do they cluster?
  - Are they correlated with gear-shift transitions (RPM/MPH ratio change)?
  - Does mrp overshoot vs Trgt_Boost precede them (boost protection)?
  - Does Tdp (target boost duty) drop right before?
  - Does Timing or AVCS spike right before?
"""
import pandas as pd, numpy as np
from pathlib import Path

OUT = Path("/sessions/epic-happy-cannon/mnt/outputs/explore")
df = pd.read_parquet(OUT / "all.parquet").sort_values(["log_id","sample"]).reset_index(drop=True)

# detect stutters and grab pre/post context
df["dthr"] = df.groupby("log_id")["Throttle"].diff()
df["dapp"] = df.groupby("log_id")["Accelerator"].diff().abs()
df["dRQTQ"] = df.groupby("log_id")["RQTQ"].diff()
df["dTdp"] = df.groupby("log_id")["Tdp"].diff()
df["dTrgt"] = df.groupby("log_id")["Trgt_Boost"].diff()
df["mph_per_rpm"] = df.MPH / df.RPM.clip(lower=1)
df["dmph_per_rpm"] = df.groupby("log_id")["mph_per_rpm"].diff()

stut_mask = (df.dthr <= -3) & (df.dapp < 1) & (df.RPM > 1500)
stut = df[stut_mask].copy()
print(f"Total stutter rows: {len(stut):,}")
print(f"Per rev:\n{stut.groupby('rev').size()}")
print()

# WHERE in the map (RPM × load bands) per rev
stut["rpm_band"] = pd.cut(stut.RPM, [0,1500,2000,2500,3000,3500,4500,7000])
stut["load_band"] = pd.cut(stut.load, [0,0.4,0.7,1.0,1.3,1.6,3.0])
print("--- Stutter cell density per rev ---")
for rev in ["20.10","20.11","20.12"]:
    s = stut[stut.rev==rev]
    if len(s)==0: continue
    print(f"\nrev {rev} (n={len(s)}):")
    ct = pd.crosstab(s.rpm_band, s.load_band, dropna=False)
    print(ct)

# co-incident-pattern: at sample of stutter, what's the local context?
# decompose by: dTrgt < -0.3 (commanded down), dRQTQ < -5 (RQTQ falling — driveline cut), mrp>Trgt (boost overshoot), dmph_per_rpm change (shift)
print("\n--- Mechanism fingerprints per rev ---")
for rev in ["20.10","20.11","20.12"]:
    s = stut[stut.rev==rev].copy()
    if len(s)==0: continue
    cmd_down = ((s.dTrgt < -0.3)).mean()*100
    rqtq_cut = ((s.dRQTQ < -5)).mean()*100
    overshoot = ((s.mrp - s.Trgt_Boost) > 0.5).mean()*100
    near_shift = (s.dmph_per_rpm.abs() > 0.001).mean()*100
    fbkc_neg = (s.FBKC < -0.1).mean()*100
    rqtq_med = s.RQTQ.median()
    print(f"rev {rev}: cmd_target_down={cmd_down:5.1f}%  RQTQ_cut={rqtq_cut:5.1f}%  boost_overshoot={overshoot:5.1f}%  near_shift={near_shift:5.1f}%  fbkc_active={fbkc_neg:5.1f}%  RQTQ_at_event_med={rqtq_med:.1f}")

# focus on 20.12 specifically — what's the dominant flavor?
print("\n--- 20.12 stutter detailed pivot ---")
s12 = stut[stut.rev=="20.12"].copy()
s12["fingerprint"] = "other"
s12.loc[s12.dmph_per_rpm.abs() > 0.001, "fingerprint"] = "shift_transient"
s12.loc[(s12.mrp - s12.Trgt_Boost) > 0.5, "fingerprint"] = "boost_overshoot"
s12.loc[s12.dRQTQ < -10, "fingerprint"] = "rqtq_drop"
s12.loc[s12.dTrgt < -0.5, "fingerprint"] = "trgt_drop"
print(s12.fingerprint.value_counts())
print()

# per-log breakdown of stutter to check if 5-17_log0002 dominates
print("--- Stutter per log (20.12) ---")
print(stut[stut.rev=="20.12"].groupby("log_id").size())

# per-active-minute (only MPH>5) rates per log
print("\n--- Stutter per active minute per log ---")
rows = []
for log_id, sub in df.groupby("log_id"):
    active_min = (sub.MPH > 5).sum() / 25 / 60
    n_stut = stut_mask.loc[sub.index].sum()
    rate = n_stut / active_min if active_min>0 else 0
    rows.append({"log_id": log_id, "rev": sub.rev.iloc[0], "active_min": round(active_min,1), "n_stut": int(n_stut), "per_min": round(rate,2)})
log_table = pd.DataFrame(rows).sort_values(["rev","log_id"])
print(log_table.to_string(index=False))
log_table.to_csv(OUT/"stutter_per_log.csv", index=False)

# Now: pull 50 worst stutter windows from 20.12 (largest drops) and dump a microview
print("\n--- 10 deepest 20.12 stutters with ±5-sample windows ---")
deepest = stut[stut.rev=="20.12"].nsmallest(10, "dthr")
for _, ev in deepest.iterrows():
    idx = ev.name
    window = df.loc[max(0,idx-5):idx+5, ["log_id","sample","RPM","Accelerator","Throttle","RQTQ","load","mrp","Trgt_Boost","Tdp","FBKC","Timing","avcs"]].copy()
    print(f"\n[{ev.log_id} sample={int(ev['sample'])}] dthr={ev.dthr:.2f}% RPM={ev.RPM:.0f} load={ev.load:.2f}")
    print(window.to_string(index=False))
