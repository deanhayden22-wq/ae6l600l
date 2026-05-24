"""
Drill into the worst-lean moments in 5-23 logs. Show context windows around each spike.
"""
from pathlib import Path
import numpy as np
import pandas as pd

LOGS = {
    "warm": Path("logs/5-23 20.14/log0001.csv"),
    "cold": Path("logs/5-23 20.14/log0002.csv"),
}

def load(p):
    d = pd.read_csv(p)
    for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
    return d.sort_values("sample").reset_index(drop=True)

def find_spikes(d, label, n=6):
    """Find isolated lean-spike peaks. Require:
       - throttle > 12% (so it's an accel/load context, not idle/overrun)
       - wbo2 in [12, 19] (exclude sensor pegging)
       - lean = wbo2 - FFB
       - take top N non-overlapping (>=2s apart) peaks
    """
    mask = (d["Throttle"] > 12) & (d["wbo2"].between(12, 19)) & (d["FFB"].between(10, 18)) & (d["RPM"] > 1000)
    sub = d.loc[mask].copy()
    sub["lean"] = sub["wbo2"] - sub["FFB"]
    sub = sub.sort_values("lean", ascending=False).reset_index(drop=False)
    picked = []
    taken_t = []
    for _, row in sub.iterrows():
        t = row["time"]
        if all(abs(t - tt) > 2.0 for tt in taken_t):
            picked.append(row)
            taken_t.append(t)
            if len(picked) >= n: break
    if not picked: return
    print(f"\n## {label}: top {len(picked)} lean spikes (filtered, throttle>12%, wbo2 in [12,19])")
    cols = ["time","RPM","MPH","Throttle","Accelerator","load","mrp","wbo2","FFB","AFR","AFC","AFL","avcs","Timing","CL/OL","FBKC","IPW","MAF"]
    rows_to_show = []
    for r in picked:
        i = int(r["index"])
        win = d.iloc[max(0,i-15):i+16][cols]  # +/- 0.6s
        win = win.copy()
        win["lean"] = win["wbo2"] - win["FFB"]
        rows_to_show.append((float(r["lean"]), float(r["time"]), win))
    for lean, t, win in sorted(rows_to_show, key=lambda x: -x[0]):
        print(f"\n  ### lean peak {lean:+.2f} AFR @ t={t:.2f}s "
              f"(wbo2={win.iloc[15]['wbo2']:.2f}, FFB={win.iloc[15]['FFB']:.2f})")
        with pd.option_context("display.max_columns", None,
                               "display.width", 200,
                               "display.float_format", "{:.2f}".format):
            print(win.to_string(index=False))

def cold_25mph_windows(d):
    """Find ~25 mph windows in cold drive and look at stutter signatures (AVCS, timing)."""
    print("\n## Cold drive: 25 mph cruise windows (rolling 2-second segments)")
    d = d.copy()
    d["t_round"] = (d["time"] // 2).astype(int)
    grp = d.groupby("t_round").agg(
        mph_mean=("MPH","mean"), mph_std=("MPH","std"),
        rpm_mean=("RPM","mean"),
        load_mean=("load","mean"),
        thr_mean=("Throttle","mean"),
        avcs_std=("avcs","std"),
        avcs_range=("avcs", lambda x: x.max()-x.min()),
        avcs_jump_max=("avcs", lambda x: x.diff().abs().max()),
        timing_std=("Timing","std"),
        n=("sample","size"),
    )
    grp = grp[(grp["mph_mean"].between(22, 30)) & (grp["mph_std"] < 2.0) & (grp["n"] >= 30) & (grp["thr_mean"].between(2, 25))]
    grp = grp.sort_values("avcs_range", ascending=False)
    print(f"  - found {len(grp)} 2-sec windows of steady 22-30 mph cruise (cold)")
    if len(grp):
        print("\n  ### Top 10 by AVCS range (worst hunt signatures):")
        with pd.option_context("display.float_format","{:.2f}".format,"display.width",160):
            print(grp.head(10).to_string())

def main():
    for lbl, p in LOGS.items():
        d = load(p)
        find_spikes(d, f"{lbl} ({p.name})")
    cold_25mph_windows(load(LOGS["cold"]))

if __name__ == "__main__":
    main()
