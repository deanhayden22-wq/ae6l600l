"""Load all 20.10/20.11/20.12 logs into a tagged DataFrame and persist as parquet."""
import pandas as pd
import os

BASE = "/sessions/epic-happy-cannon/mnt/ae6l600l/logs"

LOGS = {
    "20.10": [
        ("April/4-27 20.10/4-27.csv", "4-27"),
        ("5-2/5-2.csv", "5-2"),
    ],
    "20.11": [
        ("5-8 20.11/5-8.csv", "5-8"),
        ("5-10 20.11/log0003.csv", "5-10_log0003"),
        ("5-11 20.11/log0001.csv", "5-11_log0001"),
        ("5-11 20.11/log0002.csv", "5-11_log0002"),
        ("5-11 20.11/log0003.csv", "5-11_log0003"),
        ("5-12 20.11/5-12.csv", "5-12"),
    ],
    "20.12": [
        ("5-17 20.12/log0002.csv", "5-17_log0002"),
        ("5-17 20.12/log0003.csv", "5-17_log0003"),
        ("5-17 20.12/log0004.csv", "5-17_log0004"),
        ("5-17 20.12/log0005.csv", "5-17_log0005"),
        ("5-17 20.12/log0006.csv", "5-17_log0006"),
        ("5-17 20.12/log0007.csv", "5-17_log0007"),
    ],
}

frames = []
for rev, files in LOGS.items():
    for relpath, label in files:
        path = os.path.join(BASE, relpath)
        df = pd.read_csv(path)
        df["rev"] = rev
        df["log_id"] = label
        frames.append(df)
        print(f"  loaded {label:18s} rev={rev}  rows={len(df):,}")

big = pd.concat(frames, ignore_index=True)
print(f"\nTotal: {len(big):,} rows, {big['log_id'].nunique()} logs, {big['rev'].nunique()} revs")
print("Memory:", big.memory_usage(deep=True).sum() // 1024 // 1024, "MB")

# Persist for fast reload
big.to_parquet("/sessions/epic-happy-cannon/mnt/outputs/explore/all.parquet")
print("Saved parquet.")
