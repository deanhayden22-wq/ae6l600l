"""
Dump context around the deepest knock events so we can SEE the pattern
ourselves before tuning a shift-detector.
"""
from pathlib import Path
import pandas as pd
import numpy as np

p = Path("logs/5-23 20.14/log0003.csv")
d = pd.read_csv(p)
for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["t_rel_s"] = d["time"] - d["time"].min()
hz = len(d) / (d["time"].max() - d["time"].min())
# helpful derived columns
d["mph_per_krpm"] = np.where((d["RPM"]>800)&(d["MPH"]>5), d["MPH"]/(d["RPM"]/1000), np.nan)

# pick the 8 deepest unique knock moments (peaks separated by 4s)
k = d[d["FBKC"] < -2.0].sort_values("FBKC").reset_index(drop=False)
picked = []
taken_t = []
for _, r in k.iterrows():
    if all(abs(r["time"] - tt) > 4 for tt in taken_t):
        picked.append(int(r["index"]))
        taken_t.append(r["time"])
        if len(picked) >= 8: break

cols = ["t_rel_s","RPM","MPH","Throttle","Accelerator","load","mrp","Timing","avcs","wbo2","FFB","AFC","FBKC","FLKC","CL/OL","mph_per_krpm"]
print(f"Showing context for {len(picked)} deepest knock events (FBKC<= -2):")
for i in picked:
    lo = max(0, i-60); hi = min(len(d), i+30)
    fb = d.iloc[i]["FBKC"]; t = d.iloc[i]["t_rel_s"]
    print(f"\n{'='*120}")
    print(f"### FBKC={fb:.2f}° @ t={t:.1f}s, sample={i}, RPM={d.iloc[i]['RPM']:.0f}, MPH={d.iloc[i]['MPH']:.0f}, "
          f"Throttle={d.iloc[i]['Throttle']:.1f}%, load={d.iloc[i]['load']:.2f}, mrp={d.iloc[i]['mrp']:.1f}psi")
    with pd.option_context("display.float_format","{:.2f}".format,"display.width",200,"display.max_columns",None):
        print(d.iloc[lo:hi][cols].to_string(index=False))
