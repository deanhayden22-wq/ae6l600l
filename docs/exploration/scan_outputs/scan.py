"""Breadth-first scan: 11 angles × 3 revs. Each section produces a small CSV + console summary."""
import pandas as pd, numpy as np, os
from pathlib import Path

OUT = Path("/sessions/epic-happy-cannon/mnt/outputs/explore")
df = pd.read_parquet(OUT / "all.parquet")
df = df.sort_values(["log_id", "sample"]).reset_index(drop=True)

# helper: split into contiguous segments per log (no time gap > 1s)
def segments(sub):
    """Return contiguous segment ids per log_id based on time gaps > 1s."""
    s = sub.copy()
    dt = s.time.diff()
    s["seg"] = (dt > 1.0).cumsum()
    s["seg_key"] = s["log_id"].astype(str) + "_s" + s["seg"].astype(str)
    return s

print("="*78); print("ANGLE 1: KNOCK LEARNING DYNAMICS"); print("="*78)
# IAM trajectory & FBKC/FLKC walk
rows = []
for rev, sub in df.groupby("rev"):
    rows.append({
        "rev": rev,
        "iam_min": sub.IAM.min(),
        "iam_p05": sub.IAM.quantile(0.05),
        "iam_med": sub.IAM.median(),
        "iam_drop_events": int((sub.IAM.diff() < -0.05).sum()),  # discrete drop events
        "fbkc_min": sub.FBKC.min(),
        "fbkc_p01": sub.FBKC.quantile(0.01),
        "flkc_unique_cells": sub[sub.FLKC < 0].FLKC.nunique(),
        "max_retard_deg": -min(sub.FBKC.min(), sub.FLKC.min()),
        "knock_per_min": (sub.KNOCK_FLAG > 0).sum() / (len(sub)/25/60),
    })
pd.DataFrame(rows).to_csv(OUT/"knock_dynamics.csv", index=False)
print(pd.DataFrame(rows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 2: BOOST TRANSIENTS — rise time when commanded boost steps up"); print("="*78)
# find events where Trgt_Boost steps up by >2 psi within 0.4s while RPM>2000
# measure 90% rise time of mrp toward target
trans_rows = []
df["seg"] = (df.groupby("log_id")["time"].diff() > 1.0).cumsum()
for rev, sub in df.groupby("rev"):
    sub = sub.copy()
    sub["tb_step"] = sub.Trgt_Boost.diff()
    starts = sub[(sub.tb_step > 0.5) & (sub.RPM > 2000) & (sub.RPM < 5000) & (sub.MPH > 15)].index
    rise_times = []
    overshoots = []
    for idx in starts[:500]:
        window = sub.loc[idx:idx+125]   # 5 seconds at 25Hz
        if len(window) < 50: continue
        target = window.Trgt_Boost.iloc[5]   # target right after step
        start_mrp = window.mrp.iloc[0]
        gap = target - start_mrp
        if gap < 1.5: continue                # require meaningful gain
        thresh = start_mrp + 0.9*gap
        hit = window[window.mrp >= thresh]
        if len(hit) == 0: continue
        rt = hit.time.iloc[0] - window.time.iloc[0]
        if rt > 4: continue
        peak = window.mrp.max()
        overshoot = peak - target
        rise_times.append(rt)
        overshoots.append(overshoot)
    if rise_times:
        trans_rows.append({
            "rev": rev,
            "n_events": len(rise_times),
            "rise_p50_s": np.median(rise_times),
            "rise_p90_s": np.quantile(rise_times, 0.9),
            "overshoot_med_psi": np.median(overshoots),
            "overshoot_p90_psi": np.quantile(overshoots, 0.9),
            "overshoot_pos_rate": (np.array(overshoots) > 0.5).mean(),
        })
pd.DataFrame(trans_rows).to_csv(OUT/"transients.csv", index=False)
print(pd.DataFrame(trans_rows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 3: AFC DRIFT — closed-loop fuel trim per rev / load / RPM band"); print("="*78)
cl = df[df["CL/OL"] == 8].copy()    # CL only
cl["rpm_band"] = pd.cut(cl.RPM, [0,1200,1800,2500,3500,5000,9000], labels=["idle","1200-1800","1800-2500","2500-3500","3500-5000","5000+"])
cl["load_band"] = pd.cut(cl.load, [-1,0.5,0.8,1.0,1.3,1.6,3.0], labels=["<0.5","0.5-0.8","0.8-1.0","1.0-1.3","1.3-1.6",">1.6"])
afc_by = cl.groupby(["rev","rpm_band"], observed=True).AFC.agg(["mean","median","std","count"]).reset_index()
afc_by.columns = ["rev","rpm_band","afc_mean","afc_med","afc_std","n"]
afc_by = afc_by[afc_by.n > 200]
afc_by.to_csv(OUT/"afc_drift.csv", index=False)
print(afc_by.to_string(index=False))

print("\n"+"="*78); print("ANGLE 4: WBO2 RESIDUALS — wbo2 vs commanded FFB (lag-corrected ~8 samples)"); print("="*78)
# FFB is commanded AFR; wbo2 is measured wideband. Memory: 320ms WB lag = ~8 samples
work = df[(df.MPH > 5) & (df.wbo2 > 8) & (df.wbo2 < 22) & (df.FFB > 8) & (df.FFB < 18)].copy()
work["wbo2_lag"] = work.groupby("log_id")["wbo2"].shift(-8)   # shift backward to align with command at time t
work = work.dropna(subset=["wbo2_lag"])
work["resid"] = work.wbo2_lag - work.FFB                       # positive = leaner than commanded
work["load_band"] = pd.cut(work.load, [-1,0.5,0.8,1.0,1.3,1.6,3.0], labels=["<0.5","0.5-0.8","0.8-1.0","1.0-1.3","1.3-1.6",">1.6"])
wb_resid = work.groupby(["rev","load_band"], observed=True).resid.agg(["mean","median","std","count"]).reset_index()
wb_resid = wb_resid[wb_resid["count"] > 500]
wb_resid.columns = ["rev","load_band","resid_mean_AFR","resid_med_AFR","resid_std","n"]
wb_resid.to_csv(OUT/"wb_residuals.csv", index=False)
print(wb_resid.to_string(index=False))

print("\n"+"="*78); print("ANGLE 5: SPECTRAL — RPM oscillations at idle and steady cruise"); print("="*78)
# pick steady idle segments (MPH<2, RPM 700-1100, ≥20s contiguous) and steady cruise (CL=8, MPH 40-70, throttle std<0.5%, ≥20s)
from scipy.signal import welch
spec_rows = []
for rev in ["20.10","20.11","20.12"]:
    sub = df[df.rev == rev].copy()
    # IDLE
    idle = sub[(sub.MPH < 2) & (sub.RPM > 700) & (sub.RPM < 1100)]
    if len(idle) > 250:
        rpm_signal = idle.RPM.values.astype(float)
        # detrend / center
        rpm_signal = rpm_signal - rpm_signal.mean()
        f, P = welch(rpm_signal, fs=25, nperseg=min(512, len(rpm_signal)))
        peak_f = f[np.argmax(P[1:])+1]  # skip DC
        peak_pow = P.max()
        spec_rows.append({"rev": rev, "regime": "idle", "n_samples": len(idle), "peak_hz": peak_f, "peak_power": peak_pow, "rpm_std": float(idle.RPM.std())})
    # CRUISE
    cr = sub[(sub["CL/OL"]==8) & (sub.MPH > 40) & (sub.MPH < 70) & (sub.RPM > 1500) & (sub.RPM < 3000)]
    if len(cr) > 250:
        rpm_signal = cr.RPM.values.astype(float)
        rpm_signal = rpm_signal - rpm_signal.mean()
        f, P = welch(rpm_signal, fs=25, nperseg=min(512, len(rpm_signal)))
        peak_f = f[np.argmax(P[1:])+1]
        peak_pow = P.max()
        spec_rows.append({"rev": rev, "regime": "cruise", "n_samples": len(cr), "peak_hz": peak_f, "peak_power": peak_pow, "rpm_std": float(cr.RPM.std())})
pd.DataFrame(spec_rows).to_csv(OUT/"spectral.csv", index=False)
print(pd.DataFrame(spec_rows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 6: GEAR INFERENCE — RPM/MPH ratio clustering"); print("="*78)
mv = df[(df.MPH > 5) & (df.RPM > 800)].copy()
mv["ratio"] = mv.RPM / mv.MPH
# look at histogram, find peaks per rev
ratio_rows = []
for rev, sub in mv.groupby("rev"):
    h, edges = np.histogram(sub.ratio.clip(20, 200), bins=180)
    # smooth
    h_s = pd.Series(h).rolling(5, center=True).mean().fillna(0).values
    # top 5 peaks
    from scipy.signal import find_peaks
    peaks, props = find_peaks(h_s, distance=8, prominence=h_s.max()*0.05)
    centers = (edges[peaks] + edges[peaks+1]) / 2
    heights = h_s[peaks]
    top = sorted(zip(heights, centers), reverse=True)[:6]
    ratio_rows.append({"rev": rev, "n": len(sub), "peaks_RPMperMPH": [round(c,1) for _,c in top]})
print(pd.DataFrame(ratio_rows).to_string(index=False))
pd.DataFrame(ratio_rows).to_csv(OUT/"gear_inference.csv", index=False)

print("\n"+"="*78); print("ANGLE 7: DFCO HYGIENE — fuel-cut entry/exit"); print("="*78)
# DFCO signature: AFR ~ 20.327 (the flag value), wbo2 reads very lean, IPW likely 0
# Identify DFCO by AFR > 20 OR very low IPW with RPM>1500
dfco_rows = []
for rev, sub in df.groupby("rev"):
    sub = sub.copy()
    is_dfco = (sub.AFR > 20) | (sub.IPW < 0.3)
    # entries = transitions
    trans = is_dfco.astype(int).diff()
    entries = (trans == 1).sum()
    exits = (trans == -1).sum()
    dfco_dur = is_dfco.sum() / 25 / 60   # minutes
    # entry quality: rpm at entry
    entry_idx = sub.index[trans == 1]
    entry_rpms = sub.loc[entry_idx, "RPM"].values
    # exit quality: how harsh is fuel re-engagement? look at next-5-sample throttle/AFR jump
    exit_idx = sub.index[trans == -1]
    afc_jumps = []
    for ei in exit_idx[:300]:
        if ei+5 in sub.index:
            j = sub.loc[ei+5, "AFC"] - sub.loc[ei, "AFC"]
            afc_jumps.append(j)
    dfco_rows.append({
        "rev": rev,
        "entries": int(entries),
        "exits": int(exits),
        "dfco_min": round(float(dfco_dur), 2),
        "entry_rpm_med": float(np.median(entry_rpms)) if len(entry_rpms) else None,
        "afc_jump_at_exit_med": round(float(np.median(afc_jumps)),2) if afc_jumps else None,
        "afc_jump_at_exit_p90": round(float(np.quantile(afc_jumps, 0.9)),2) if afc_jumps else None,
    })
pd.DataFrame(dfco_rows).to_csv(OUT/"dfco.csv", index=False)
print(pd.DataFrame(dfco_rows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 8: DRIVER BEHAVIOR — pedal/throttle distributions"); print("="*78)
# accelerator usage histogram per rev (active driving: MPH>5)
drv_rows = []
for rev, sub in df.groupby("rev"):
    active = sub[sub.MPH > 5]
    drv_rows.append({
        "rev": rev,
        "minutes_active": round(len(active)/25/60, 1),
        "app_med": float(active.Accelerator.median()),
        "app_p90": float(active.Accelerator.quantile(0.9)),
        "app_p99": float(active.Accelerator.quantile(0.99)),
        "thr_med": float(active.Throttle.median()),
        "thr_p90": float(active.Throttle.quantile(0.9)),
        "thr_p99": float(active.Throttle.quantile(0.99)),
        "wot_seconds": int((active.Throttle > 95).sum())/25,
        "mph_med": float(active.MPH.median()),
        "mph_p90": float(active.MPH.quantile(0.9)),
        "mph_p99": float(active.MPH.quantile(0.99)),
    })
pd.DataFrame(drv_rows).to_csv(OUT/"driver_behavior.csv", index=False)
print(pd.DataFrame(drv_rows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 9: SENSOR QUANTIZATION — minimum step size per channel"); print("="*78)
# per channel, find smallest nonzero diff abs across the dataset → that's the LSB
qrows = []
for c in ["wbo2","AFR","FFB","EGT","AFC","RPM","load","MPH","Timing","IAT","MAF","MAF(V)","Accelerator","Throttle","RQTQ","MAP","mrp","Trgt_Boost","IAM","FLKC","FBKC","avcs","wgdc","tdi","Tdp","IPW","IDC"]:
    if c not in df.columns: continue
    d = df[c].diff().abs()
    d = d[d > 0]
    if len(d) == 0: continue
    lsb = d.quantile(0.001)   # robust min
    n_unique = df[c].nunique()
    qrows.append({"col": c, "n_unique": n_unique, "lsb_est": lsb, "min": float(df[c].min()), "max": float(df[c].max())})
pd.DataFrame(qrows).to_csv(OUT/"sensor_quant.csv", index=False)
print(pd.DataFrame(qrows).to_string(index=False))

print("\n"+"="*78); print("ANGLE 10: CROSS-CHANNEL COUPLING — correlation shifts between revs"); print("="*78)
# compute correlation of (Timing, avcs, wbo2, EGT, FBKC, FLKC, AFC) within cruise per rev
cruise = df[(df["CL/OL"]==8) & (df.MPH>20) & (df.Accelerator>2) & (df.Accelerator<25)]
cols = ["Timing","avcs","wbo2","EGT","FBKC","FLKC","AFC","MAF(V)","RPM","load"]
print(f"cruise rows: {len(cruise):,}")
for rev in ["20.10","20.11","20.12"]:
    sub = cruise[cruise.rev==rev][cols]
    if len(sub) < 1000: continue
    corr = sub.corr()
    # save corr matrix
    corr.to_csv(OUT/f"corr_{rev.replace('.','_')}.csv")
print("Saved per-rev correlation matrices. (See diffs in drill phase.)")

print("\n"+"="*78); print("ANGLE 11: SURPRISE — Stutter events (per rev_map: 980+ on 5-17_log0002)"); print("="*78)
# Stutter pattern: rapid throttle drop while pedal is steady — investigate signature
# Detect: at sample t, Throttle drops by ≥3% in one sample, Accelerator change <1%
df_sorted = df.sort_values(["log_id","sample"])
df_sorted["dthr"] = df_sorted.groupby("log_id")["Throttle"].diff()
df_sorted["dapp"] = df_sorted.groupby("log_id")["Accelerator"].diff().abs()
stutter = df_sorted[(df_sorted.dthr < -3) & (df_sorted.dapp < 1) & (df_sorted.RPM > 1500)].copy()
stut_rows = []
for rev, sub in stutter.groupby("rev"):
    drive_min = df[df.rev==rev].pipe(lambda x: len(x[x.MPH>5]))/25/60
    stut_rows.append({
        "rev": rev,
        "stutters": int(len(sub)),
        "per_active_min": round(len(sub)/drive_min, 2),
        "median_drop_pct": float(sub.dthr.median()),
        "p10_drop_pct": float(sub.dthr.quantile(0.10)),
        "rpm_med_at_event": float(sub.RPM.median()),
        "load_med_at_event": float(sub.load.median()),
        "in_boost_pct": float((sub.mrp > 2).mean()*100),
    })
pd.DataFrame(stut_rows).to_csv(OUT/"stutter.csv", index=False)
print(pd.DataFrame(stut_rows).to_string(index=False))

print("\nDone.")
