"""
Sweep log0003 for tip-in-shortfall lean events: throttle ramping in OL with
wbo2 going lean of FFB by >= 2 AFR for >= 100ms.

Goal: gauge whether the 105349 event is a one-off or systemic, and characterize
the throttle-rate distribution of these events.
"""
from pathlib import Path
import numpy as np
import pandas as pd

p = Path("logs/5-23 20.14/log0003.csv")
d = pd.read_csv(p)
for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["t_rel_s"] = d["time"] - d["time"].min()
hz = len(d) / (d["time"].max() - d["time"].min())
dt = 1.0 / hz

# per-sample throttle change (the actual tip-in input)
d["throttle_d_per_sample"] = d["Throttle"].diff()
# rolling 3-sample (max ~160ms) throttle change accumulator
d["throttle_d_3"] = d["Throttle"].diff().rolling(3, min_periods=1).sum()

# lean signal
d["lean"] = d["wbo2"] - d["FFB"]

# Mask: real throttle activity (not idle), engine running, in OL, wbo2 valid
in_window = (
    (d["RPM"] > 1200)
    & (d["CL/OL"] == 10)
    & (d["Throttle"] > 8)
    & (d["wbo2"].between(13, 19.5))   # exclude pegging + lambda steady
    & (d["FFB"].between(10, 16))
)

# A "lean event" sample: lean >= 2.0 AFR AND throttle just opened
event_mask = in_window & (d["lean"] >= 2.0) & (d["throttle_d_3"] > 1.5)

# Find contiguous runs >= 2 samples (~100ms+)
arr = event_mask.to_numpy()
runs = []
i = 0
while i < len(arr):
    if arr[i]:
        j = i
        while j < len(arr) and arr[j]:
            j += 1
        if j - i >= 2:
            runs.append((i, j-1))
        i = j
    else:
        i += 1
print(f"Found {len(runs)} tip-in-shortfall lean events ({len(arr)} samples total, sample rate {hz:.1f} Hz)")

# Per-event stats
events = []
for (a, b) in runs:
    # also look at the 0.5s WINDOW around to grab the peak
    a2 = max(0, a-5); b2 = min(len(d)-1, b+5)
    seg = d.iloc[a2:b2+1]
    sample0 = d.iloc[a]
    events.append({
        "t_start_s": float(sample0["t_rel_s"]),
        "dur_s": (b - a + 1) * dt,
        "rpm_at_start": float(sample0["RPM"]),
        "mph_at_start": float(sample0["MPH"]),
        "throttle_start": float(sample0["Throttle"]),
        "throttle_peak": float(seg["Throttle"].max()),
        "throttle_step": float(seg["Throttle"].max() - sample0["Throttle"]),
        "throttle_d_per_sample_max": float(seg["throttle_d_per_sample"].max()),
        "throttle_d_3_max": float(seg["throttle_d_3"].max()),
        "load_peak": float(seg["load"].max()),
        "mrp_peak": float(seg["mrp"].max()),
        "lean_peak": float(seg["lean"].max()),
        "wbo2_peak": float(seg["wbo2"].max()),
        "ffb_at_peak": float(seg.loc[seg["wbo2"].idxmax(), "FFB"]),
        "avcs_d": float(seg["avcs"].max() - seg["avcs"].min()),
        "fbkc_within_2s_later": float(d.iloc[b:min(len(d), b+int(2*hz))]["FBKC"].min()) if b+1 < len(d) else 0.0,
    })

ev = pd.DataFrame(events)
print(f"\nThrottle per-sample-change distribution at event onset:")
print(f"  max per-sample throttle change: median {ev['throttle_d_per_sample_max'].median():.2f}%, max {ev['throttle_d_per_sample_max'].max():.2f}%")
print(f"  % of events with max per-sample step > 2.0% (tip-in activation): {(ev['throttle_d_per_sample_max']>2.0).mean()*100:.1f}%")
print(f"  % of events with max per-sample step > 1.0%: {(ev['throttle_d_per_sample_max']>1.0).mean()*100:.1f}%")
print(f"  median throttle peak: {ev['throttle_peak'].median():.1f}%")
print(f"  median lean peak: {ev['lean_peak'].median():.2f} AFR")
print(f"  median load_peak: {ev['load_peak'].median():.2f} g/rev")
print(f"  median mrp_peak: {ev['mrp_peak'].median():.2f} psi")
print(f"  median RPM at start: {ev['rpm_at_start'].median():.0f}")

print(f"\nEvents that drew FBKC<0 within 2s after:")
print(f"  any FBKC: {(ev['fbkc_within_2s_later'] < 0).sum()} of {len(ev)} ({(ev['fbkc_within_2s_later']<0).mean()*100:.1f}%)")
print(f"  FBKC <= -4: {(ev['fbkc_within_2s_later'] <= -4).sum()}")
print(f"  FBKC <= -2: {(ev['fbkc_within_2s_later'] <= -2).sum()}")

print(f"\nTop 10 worst lean events:")
top = ev.sort_values("lean_peak", ascending=False).head(10)
with pd.option_context("display.float_format","{:.2f}".format,"display.width",200):
    print(top.to_string(index=False))

# distribution by RPM band
print(f"\nLean events by RPM band:")
ev["rpm_band"] = pd.cut(ev["rpm_at_start"], [1200, 1800, 2400, 3000, 3600, 4500, 6000])
g = ev.groupby("rpm_band", observed=True).agg(
    n=("lean_peak","size"),
    med_lean=("lean_peak","median"),
    med_throttle_step=("throttle_step","median"),
    med_throttle_d_max=("throttle_d_per_sample_max","median"),
    fbkc_followups=("fbkc_within_2s_later", lambda x: (x<0).sum()),
)
print(g.to_string())
