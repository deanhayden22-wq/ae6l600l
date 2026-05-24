"""
Deep review of the big way-home log (5-23 log0003, 253 min on 20.14).

Sections:
  1. Knock map: where the 699 FBKC events fired, severity, AVCS context
  2. WOT pulls: extract the WOT events, fueling/timing/knock during pull
  3. AVCS-sweep lean check (still happening on accel?)
  4. Highway cruise behavior (16.5% APP / 2800-3600 hunt band per memory)
  5. AFC/AFL movement vs prior logs
  6. FLKC latch — where & how deep
"""
from __future__ import annotations
from pathlib import Path
import pandas as pd
import numpy as np

LOG = Path("logs/5-23 20.14/log0003.csv")

# ROM grids from log_review_ingest
RPM_BP = np.array([800,1200,1600,1900,2200,2600,3000,3300,3700,4000,4400,4800,5200,5500,6000,6300,6600,7000],dtype=float)
LOAD_BP = np.array([0.27,0.57,0.73,1.00,1.17,1.36,1.51,1.64,1.78,1.95,2.12,2.28,2.44,2.6,2.9,3.22,3.7],dtype=float)

def nearest_bp(v, bp):
    if pd.isna(v): return np.nan
    return float(bp[np.argmin(np.abs(bp - v))])

def load():
    d = pd.read_csv(LOG)
    for c in d.columns:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.sort_values("sample").reset_index(drop=True)
    d["t_rel_s"] = d["time"] - d["time"].min()
    # nearest grid bins
    d["rpm_bin"] = d["RPM"].apply(lambda x: nearest_bp(x, RPM_BP))
    d["load_bin"] = d["load"].apply(lambda x: nearest_bp(x, LOAD_BP))
    return d

def section_header(t): print(f"\n{'='*72}\n## {t}\n{'='*72}")

# ---------- 1. Knock map ----------
def knock_map(d):
    section_header("KNOCK MAP")
    print(f"Total samples: {len(d):,}  Drive time: {(d['time'].max()-d['time'].min())/60:.1f} min")
    print(f"FBKC<0 samples: {(d['FBKC']<0).sum():,}  min FBKC {d['FBKC'].min():.2f} deg")
    print(f"FLKC<0 samples: {(d['FLKC']<0).sum():,}  min FLKC {d['FLKC'].min():.2f} deg")
    print(f"Both pulled (FBKC<0 AND FLKC<0): {((d['FBKC']<0)&(d['FLKC']<0)).sum():,}")
    print(f"FBKC=-8.0 samples (worst): {(d['FBKC']<=-7.5).sum():,}")

    # per-cell breakdown
    k = d[d["FBKC"] < 0].copy()
    cell = k.groupby(["rpm_bin","load_bin"]).agg(
        n=("FBKC","size"),
        min_fbkc=("FBKC","min"),
        med_fbkc=("FBKC","median"),
        avcs_med=("avcs","median"),
        timing_med=("Timing","median"),
        mrp_med=("mrp","median"),
        ol_pct=("CL/OL", lambda x: (x==10).mean()*100),
        wbo2_med=("wbo2","median"),
        ffb_med=("FFB","median"),
    ).reset_index().sort_values("n", ascending=False).head(15)
    print("\nTop 15 knock cells (by FBKC<0 sample count):")
    with pd.option_context("display.float_format","{:.2f}".format,"display.width",160):
        print(cell.to_string(index=False))

    # FLKC latched - where
    flkc = d[d["FLKC"] < 0].copy()
    if len(flkc):
        fcell = flkc.groupby(["rpm_bin","load_bin"]).agg(
            n=("FLKC","size"), min_flkc=("FLKC","min"),
            avcs_med=("avcs","median"), mrp_med=("mrp","median"),
        ).reset_index().sort_values("n", ascending=False).head(10)
        print("\nFLKC latch zones (top 10 by sample count):")
        with pd.option_context("display.float_format","{:.2f}".format,"display.width",140):
            print(fcell.to_string(index=False))

# ---------- 2. WOT pulls ----------
def wot_pulls(d):
    section_header("WOT PULLS")
    # find TPS>=95 runs >=10 samples
    is_wot = (d["Throttle"] >= 95).to_numpy()
    runs = []
    i = 0
    while i < len(d):
        if is_wot[i]:
            j = i
            while j < len(d) and is_wot[j]:
                j += 1
            if j - i >= 10:
                runs.append((i, j-1))
            i = j
        else:
            i += 1
    print(f"Found {len(runs)} WOT pulls (TPS>=95% for >=10 samples)")
    for k, (a, b) in enumerate(runs, 1):
        win = d.iloc[max(0,a-30):min(len(d),b+30)]
        seg = d.iloc[a:b+1]
        print(f"\n  ### WOT #{k}  t={d.iloc[a]['t_rel_s']:.1f}s, samples {a}-{b} ({b-a+1} samp / {(b-a+1)*0.053:.1f}s @ 18.8Hz)")
        print(f"  RPM {seg['RPM'].min():.0f} -> {seg['RPM'].max():.0f}, "
              f"MPH {seg['MPH'].min():.0f} -> {seg['MPH'].max():.0f}, "
              f"mrp peak {seg['mrp'].max():.2f} psi, "
              f"MAP peak {seg['MAP'].max():.2f} psi")
        print(f"  CL/OL during pull: CL={ (seg['CL/OL']==8).mean()*100:.0f}%, OL={(seg['CL/OL']==10).mean()*100:.0f}%")
        print(f"  wbo2 range: {seg['wbo2'].min():.2f} - {seg['wbo2'].max():.2f}, "
              f"FFB target range: {seg['FFB'].min():.2f} - {seg['FFB'].max():.2f}")
        print(f"  knock during pull: FBKC<0 = {(seg['FBKC']<0).sum()} samples, min {seg['FBKC'].min():.2f} deg")
        print(f"  IDC peak: {seg['IDC'].max():.1f}%, IPW peak: {seg['IPW'].max():.2f} ms")
        # show the pull
        cols = ["t_rel_s","RPM","MPH","Throttle","load","mrp","Timing","avcs",
                "wbo2","FFB","AFC","AFL","FBKC","FLKC","IDC","CL/OL","IAT"]
        with pd.option_context("display.float_format","{:.2f}".format,"display.width",200,"display.max_columns",None):
            print("  Pull trace (every 2 samples):")
            print(win[cols].iloc[::2].to_string(index=False))

# ---------- 3. AVCS-sweep lean check ----------
def avcs_lean_spikes(d):
    section_header("AVCS-SWEEP LEAN SPIKES (still happening?)")
    # find isolated lean peaks under accel
    mask = (d["Throttle"] > 12) & (d["wbo2"].between(12, 19)) & (d["FFB"].between(10, 18)) & (d["RPM"] > 1000)
    sub = d.loc[mask].copy()
    sub["lean"] = sub["wbo2"] - sub["FFB"]
    sub = sub.sort_values("lean", ascending=False).reset_index(drop=False)
    picked = []
    taken_t = []
    for _, row in sub.iterrows():
        t = row["time"]
        if all(abs(t - tt) > 4.0 for tt in taken_t):
            picked.append(row); taken_t.append(t)
            if len(picked) >= 8: break
    print(f"Top {len(picked)} isolated lean spikes (filtered, throttle>12%, wbo2 in [12,19]):")
    for r in picked:
        i = int(r["index"])
        win = d.iloc[max(0,i-12):i+13]
        win = win.copy()
        win["lean"] = win["wbo2"] - win["FFB"]
        avcs_range = win["avcs"].max() - win["avcs"].min()
        avcs_jump = win["avcs"].diff().abs().max()
        print(f"\n  t={float(r['time']):.1f}s  RPM≈{int(r['RPM'])}  MPH={int(r['MPH'])}  "
              f"lean_peak={float(r['lean']):+.2f}  AVCS Δ={avcs_range:.0f} deg  AVCS max jump={avcs_jump:.0f} deg")
        cols = ["t_rel_s","RPM","MPH","Throttle","load","mrp","wbo2","FFB","lean","AFC","avcs","Timing","CL/OL","FBKC"]
        with pd.option_context("display.float_format","{:.2f}".format,"display.width",170,"display.max_columns",None):
            print(win[cols].to_string(index=False))

# ---------- 4. Highway cruise hunt band ----------
def highway_hunt(d):
    section_header("HIGHWAY HUNT BAND (16.5% APP / 2800-3600 RPM per memory)")
    h = d[(d["MPH"].between(60, 95)) & (d["Throttle"].between(5, 25)) & (d["RPM"].between(2400, 4200))].copy()
    print(f"highway cruise samples (60-95 mph, 5-25% throttle): {len(h):,} of {len(d):,} ({len(h)/len(d)*100:.1f}%)")
    if len(h) > 100:
        # 5-sec windows in steady cruise
        h["t_round_5s"] = (h["t_rel_s"] // 5).astype(int)
        agg = h.groupby("t_round_5s").agg(
            n=("RPM","size"),
            mph_mean=("MPH","mean"),
            rpm_mean=("RPM","mean"),
            load_mean=("load","mean"),
            thr_mean=("Throttle","mean"),
            thr_std=("Throttle","std"),
            app_mean=("Accelerator","mean"),
            avcs_std=("avcs","std"),
            timing_std=("Timing","std"),
        )
        steady = agg[(agg["n"]>=80) & (agg["thr_std"]<2.0) & (agg["mph_mean"].between(60,95))]
        print(f"\nsteady 5-sec windows (n>=80, thr_std<2): {len(steady)}")
        if len(steady):
            print("\n  Top 10 by AVCS std (most cam hunt at highway cruise):")
            with pd.option_context("display.float_format","{:.2f}".format,"display.width",150):
                print(steady.sort_values("avcs_std", ascending=False).head(10).to_string())
            print(f"\n  Highway cruise summary: mean APP {steady['app_mean'].mean():.1f}%, "
                  f"mean throttle {steady['thr_mean'].mean():.1f}%, "
                  f"mean RPM {steady['rpm_mean'].mean():.0f}, "
                  f"mean AVCS std {steady['avcs_std'].mean():.2f}°")

# ---------- 5. AFC/AFL movement ----------
def afc_afl(d):
    section_header("AFC/AFL TRENDS")
    # filter to running, in-CL (where AFC is meaningful)
    cl = d[(d["RPM"]>1000) & (d["CL/OL"]==8)].copy()
    print(f"CL samples (RPM>1000): {len(cl):,}")
    print(f"AFC: mean {cl['AFC'].mean():+.2f}%, median {cl['AFC'].median():+.2f}%, std {cl['AFC'].std():.2f}%")
    print(f"AFC quartiles: 25%={cl['AFC'].quantile(0.25):+.2f}, 75%={cl['AFC'].quantile(0.75):+.2f}")
    print(f"AFC magnitude: |AFC|>5%: {(cl['AFC'].abs()>5).mean()*100:.1f}% of CL samples")
    print(f"AFL trajectory: start {cl['AFL'].iloc[0]:+.2f}, end {cl['AFL'].iloc[-1]:+.2f}, "
          f"unique values: {sorted(cl['AFL'].unique())[:10]}")
    # AFC by RPM band
    cl["rpm_band"] = pd.cut(cl["RPM"], [0,1500,2200,2800,3400,4200,5500,8000])
    print("\nAFC by RPM band:")
    afc_band = cl.groupby("rpm_band", observed=True)["AFC"].agg(["mean","std","count"])
    with pd.option_context("display.float_format","{:+.2f}".format):
        print(afc_band.to_string())

def main():
    print("loading log0003...")
    d = load()
    knock_map(d)
    wot_pulls(d)
    avcs_lean_spikes(d)
    highway_hunt(d)
    afc_afl(d)

if __name__ == "__main__":
    main()
