"""
Identify exactly when the CL/OL=7 warmup phase ENDS and wbo2 is fully warm.
Dean noted he drove off before CL/OL=7 finished. We need a 't_warm' cutoff
after which the rest of the log can be scored against 20.15 tip-in gates
without cold-wbo2 contamination.
"""
from pathlib import Path
import numpy as np
import pandas as pd

p = Path("logs/5-25 20.15/log0001.csv")
d = pd.read_csv(p)
for c in d.columns:
    d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["t_rel_s"] = d["time"] - d["time"].min()
hz = len(d) / d["t_rel_s"].max()

# Last sample where CL/OL=7 fires
last_cl7_idx = d.index[d["CL/OL"] == 7].max()
last_cl7_t = d.loc[last_cl7_idx, "t_rel_s"]
print(f"Last CL/OL=7 sample: idx={last_cl7_idx}, t={last_cl7_t:.1f}s ({last_cl7_t/60:.2f} min)")

# Show CL/OL=7 transitions
d["cl_change"] = d["CL/OL"].diff().fillna(0)
trans_to_7 = d[(d["CL/OL"] == 7) & (d["cl_change"] != 0)]
trans_from_7 = d[(d["CL/OL"].shift(1) == 7) & (d["CL/OL"] != 7)]
print(f"\nNumber of transitions INTO CL/OL=7: {len(trans_to_7)}")
print(f"Number of transitions OUT OF CL/OL=7: {len(trans_from_7)}")

# Bucket the log into 60-second windows; show CL/OL=7 fraction per window
print(f"\nCL/OL=7 fraction by 60s window:")
d["bucket"] = (d["t_rel_s"] // 60).astype(int)
buckets = d.groupby("bucket").apply(
    lambda g: pd.Series({
        "t_start": g["t_rel_s"].min(),
        "t_end": g["t_rel_s"].max(),
        "n": len(g),
        "cl7_frac": (g["CL/OL"] == 7).mean(),
        "cl8_frac": (g["CL/OL"] == 8).mean(),
        "cl10_frac": (g["CL/OL"] == 10).mean(),
        "wbo2_invalid_frac": ((g["wbo2"] >= 20) | (g["wbo2"] <= 7)).mean(),
        "wbo2_mean_valid": g.loc[g["wbo2"].between(10, 19.5), "wbo2"].mean(),
        "mph_mean": g["MPH"].mean(),
    }),
    include_groups=False,
)
print(buckets.round(3).to_string())

# Show wbo2 invalid (>=20) — that's how long until O2 sensor is fully warm
wbo2_invalid = (d["wbo2"] >= 20) | (d["wbo2"] <= 7)
# Last invalid sample
if wbo2_invalid.any():
    last_invalid_idx = d.index[wbo2_invalid].max()
    print(f"\nLast wbo2-invalid sample: idx={last_invalid_idx}, t={d.loc[last_invalid_idx, 't_rel_s']:.1f}s")

# Forward-looking: rolling 30s validity rate
d["wbo2_valid"] = ~wbo2_invalid
d["valid_30s"] = d["wbo2_valid"].rolling(int(30*hz), min_periods=1).mean()
# First moment we're >99% valid for 30s straight
warm_mask = d["valid_30s"] > 0.99
if warm_mask.any():
    t_warm_wbo2 = d.loc[warm_mask, "t_rel_s"].iloc[0]
    print(f"First t with 30s-rolling wbo2-valid >99%: {t_warm_wbo2:.1f}s")
