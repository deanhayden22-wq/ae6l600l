"""
Deep drill on the -8.05 knock event around sample 105385 in log0003.

Dean's narrative:
  - sample 105145: shift to 5th
  - accelerated up to 71-72 mph
  - let off the pedal
  - sample 105324: gets back on the pedal
  - driveline re-engages, foot bobbles
  - solid shove into 20-25% throttle
  - AFR shoots from decent to 16.7
  - timing at 24, AVCS ramping 0->20
  - load zips over 1 g/rev, mrp still a few psi short of zero (sub-atm)
  - sea level, IAT 75F

Goal: distinguish tip-in (accel enrichment shortfall) vs tau (load filter
sluggishness). Show rate-of-change of throttle, MAF, load, IPW so we can
see which one is lagging.
"""
from pathlib import Path
import numpy as np
import pandas as pd

d = pd.read_csv("logs/5-23 20.14/log0003.csv")
for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["t_rel_s"] = d["time"] - d["time"].min()
dt_s = float(np.median(np.diff(d["time"].to_numpy())))
hz = 1.0 / dt_s
print(f"sample rate: {hz:.2f} Hz, dt={dt_s*1000:.1f} ms/sample")

# derived
d["mph_per_krpm"] = np.where((d["RPM"]>800)&(d["MPH"]>10), d["MPH"]/(d["RPM"]/1000), np.nan)
# rate of change per second
d["d_throttle_per_s"] = d["Throttle"].diff() / dt_s
d["d_load_per_s"] = d["load"].diff() / dt_s
d["d_maf_per_s"] = d["MAF"].diff() / dt_s
d["d_ipw_per_s"] = d["IPW"].diff() / dt_s
d["d_rpm_per_s"] = d["RPM"].diff() / dt_s
# implied AFR from IPW & MAF (rough): fueling = MAF / (mass per IPW)
# but more useful: ratio MAF/IPW which should be roughly proportional to commanded AFR
# Actually just look at FFB vs wbo2 explicitly

# Window: 105100 - 105420 (let context breathe a bit either side)
LO, HI = 105100, 105430
w = d.iloc[LO:HI+1].copy()
print(f"\nwindow: samples {LO}-{HI} = t={w['t_rel_s'].iloc[0]:.2f} -> t={w['t_rel_s'].iloc[-1]:.2f}s "
      f"({(w['t_rel_s'].iloc[-1]-w['t_rel_s'].iloc[0]):.1f}s)")

# annotate key samples
key_samples = {105145: "DEAN: shift to 5th",
               105324: "DEAN: back on pedal",
               105385: "DEAN: -8.05 knock peak"}

# columns to show
cols = ["sample","t_rel_s","RPM","MPH","mph_per_krpm","Throttle","Accelerator","load","mrp",
        "MAF","wbo2","FFB","AFC","AFL","IPW","Timing","avcs","FBKC","FLKC","CL/OL","EGT","IAT"]

print("\n========== FULL WINDOW (every other sample for readability) ==========")
with pd.option_context("display.float_format","{:.2f}".format,"display.width",220,"display.max_columns",None):
    sub = w[cols].copy()
    sub["note"] = sub["sample"].map(lambda s: key_samples.get(int(s), ""))
    print(sub.iloc[::2].to_string(index=False))

# Now compute key transition moments
# 1. shift moment (105145) - verify mph_per_krpm jump
shift_check = d.iloc[105140:105170][["sample","t_rel_s","RPM","MPH","mph_per_krpm","Throttle","load"]]
print("\n========== SHIFT VERIFICATION (105140-105170) ==========")
with pd.option_context("display.float_format","{:.2f}".format,"display.width",140):
    print(shift_check.to_string(index=False))

# 2. lift to re-engage zone (105260-105335)
print("\n========== LIFT / RE-ENGAGE WINDOW (105260-105335) ==========")
sub2 = d.iloc[105260:105336][["sample","t_rel_s","RPM","MPH","Throttle","Accelerator","load","mrp","MAF","wbo2","FFB","IPW","avcs","EGT","CL/OL"]]
with pd.option_context("display.float_format","{:.2f}".format,"display.width",180):
    print(sub2.to_string(index=False))

# 3. the lean spike with rates of change (105330-105410)
print("\n========== LEAN SPIKE + RATES (105330-105410) ==========")
rate_cols = ["sample","t_rel_s","Throttle","d_throttle_per_s","load","d_load_per_s","MAF","d_maf_per_s","IPW","d_ipw_per_s","wbo2","FFB","AFC","avcs","Timing","EGT","FBKC"]
sub3 = d.iloc[105330:105411][rate_cols]
with pd.option_context("display.float_format","{:.2f}".format,"display.width",220):
    print(sub3.to_string(index=False))

# Summary of the lean moment
print("\n========== LEAN PEAK SUMMARY ==========")
# find peak lean in 105330-105400
peak_idx = d.iloc[105330:105400]["wbo2"].sub(d.iloc[105330:105400]["FFB"]).idxmax()
print(f"peak lean at sample {peak_idx}, t={d.iloc[peak_idx]['t_rel_s']:.2f}s")
print(f"  wbo2={d.iloc[peak_idx]['wbo2']:.2f}, FFB={d.iloc[peak_idx]['FFB']:.2f}, lean=+{d.iloc[peak_idx]['wbo2']-d.iloc[peak_idx]['FFB']:.2f} AFR")
print(f"  Throttle={d.iloc[peak_idx]['Throttle']:.1f}%, accelerator={d.iloc[peak_idx]['Accelerator']:.1f}%")
print(f"  load={d.iloc[peak_idx]['load']:.2f}, mrp={d.iloc[peak_idx]['mrp']:.2f} psi, MAF={d.iloc[peak_idx]['MAF']:.1f} g/s")
print(f"  IPW={d.iloc[peak_idx]['IPW']:.2f} ms, AVCS={d.iloc[peak_idx]['avcs']}, Timing={d.iloc[peak_idx]['Timing']:.1f}, EGT={d.iloc[peak_idx]['EGT']:.1f}")

# Was AFC reacting?
print(f"  AFC at peak: {d.iloc[peak_idx]['AFC']:.2f}%")
afc_5s_before = d.iloc[peak_idx-94:peak_idx]["AFC"]  # 5s @ 18.8Hz
print(f"  AFC 5s before peak: min={afc_5s_before.min():.2f}, max={afc_5s_before.max():.2f}")
print(f"  AFC 5s AFTER peak: shown below")

# How fast did MAF change vs load?
print(f"\n  MAF g/s change in 0.5s before peak: {d.iloc[peak_idx]['MAF']-d.iloc[peak_idx-9]['MAF']:+.1f} g/s ({(d.iloc[peak_idx]['MAF']-d.iloc[peak_idx-9]['MAF'])/0.5:+.1f} g/s/s)")
print(f"  load change in 0.5s before peak: {d.iloc[peak_idx]['load']-d.iloc[peak_idx-9]['load']:+.2f} g/rev")
print(f"  IPW change in 0.5s before peak: {d.iloc[peak_idx]['IPW']-d.iloc[peak_idx-9]['IPW']:+.2f} ms")
