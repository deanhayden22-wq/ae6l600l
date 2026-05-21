"""Quick per-rev distribution check before deep analyses."""
import pandas as pd
import numpy as np

df = pd.read_parquet("/sessions/epic-happy-cannon/mnt/outputs/explore/all.parquet")
print(f"Total rows: {len(df):,}")
print()

# Per rev: total minutes, sampling rate check, channels worth profiling
for rev in ["20.10", "20.11", "20.12"]:
    sub = df[df.rev == rev]
    # estimated minutes — assume 25 Hz
    minutes = len(sub) / 25 / 60
    # FBKC = fine learn (current correction), FLKC = active retard learn store
    # KNOCK_FLAG nonzero = knock event
    knock_rows = int((sub.KNOCK_FLAG > 0).sum())
    fbkc_neg_rows = int((sub.FBKC < 0).sum())   # active retard happening
    flkc_neg_rows = int((sub.FLKC < 0).sum())   # learned retard cells
    iam_min, iam_max = float(sub.IAM.min()), float(sub.IAM.max())
    print(f"rev {rev}: rows={len(sub):>7,} min={minutes:6.1f} knock_flag>0={knock_rows:>4} fbkc<0={fbkc_neg_rows:>5} flkc<0={flkc_neg_rows:>5} IAM=[{iam_min:.2f},{iam_max:.2f}]")

print("\n--- Time delta sampling sanity (per log) ---")
for log_id in df.log_id.unique():
    sub = df[df.log_id == log_id]
    if "time" in sub.columns:
        dt = sub.time.diff().dropna()
        med = float(dt.median()); std = float(dt.std()); n_gap = int((dt > 0.1).sum())
        rev = sub.rev.iloc[0]
        print(f"  {log_id:18s} rev={rev}  median_dt={med:.4f}s  std={std:.4f}  gaps>100ms={n_gap}")
