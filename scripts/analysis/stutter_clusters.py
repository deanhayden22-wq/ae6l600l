#!/usr/bin/env python3
"""
Regenerate stutter_clusters.csv from stutter_events.csv.

stutter_clusters.csv is the per-cluster detail behind the cross-thread
"stutter signature" metric: 500 ms windows that contain >= 2 distinct
signal types. scorecard.py (m_stutter_signature) computes the per-minute
*rate* with this exact windowing; this script emits one row per cluster
for the dashboard's cluster-distribution panels.

The anchor/window/consume loop here is byte-for-byte the same as
scorecard.m_stutter_signature, so per rev:

    len(clusters for rev) == scorecard stutter_signature n_events for rev

Validated 2026-05-24: against the prior stutter_clusters.csv, signal_set
matched 100% (954/954 joinable rows) and dominant_signal matched 100%
under the "anchor" rule (dominant = signal of the cluster's earliest
event). Per-rev counts reproduced scorecard's stutter_signature exactly.

This script exists because stutter_clusters.csv was previously orphaned:
no script regenerated it, so it went stale at rev 20.11 and the
dashboard's cluster panels silently emptied from rev 20.12 onward.

Output: scripts/analysis/trends/stutter_clusters.csv

Usage:
    python3 scripts/analysis/stutter_clusters.py
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"

# Mirror scorecard.py exactly.
STUTTER_SIG_MIN_SIGNALS = 2
STUTTER_SIG_WINDOW_S = 0.5

# Mirror dashboard.py / scorecard.py REV_ORDER for stable output ordering.
REV_ORDER = [
    "old_2023_base", "stock", "20.7", "20.8", "20.9", "20.10", "20.11",
    "20.12", "20.13", "20.14",
]

OUT_COLUMNS = [
    "rom_rev", "log_path", "start_time", "n_events", "n_signals",
    "signal_set", "dominant_signal", "rpm_mean", "load_mean", "app_mean",
    "throttle_mean",
]


def build_clusters(stutter_df: pd.DataFrame) -> pd.DataFrame:
    """Cluster stutter events into >=2-distinct-signal 500 ms windows.

    Algorithm per log (identical to scorecard.m_stutter_signature):
      1. Sort events by start_time.
      2. From an unconsumed anchor, gather every unconsumed event whose
         start_time is within STUTTER_SIG_WINDOW_S of the anchor.
      3. If the gathered set spans >= STUTTER_SIG_MIN_SIGNALS distinct
         signal types it is a cluster: consume its members and advance the
         anchor past the window. Otherwise advance the anchor by one.

    dominant_signal = signal of the anchor (earliest) event.
    """
    rows = []
    for log_path, grp in stutter_df.groupby("log_path"):
        grp = grp.sort_values("start_time").reset_index(drop=True)
        n = len(grp)
        used = np.zeros(n, dtype=bool)
        i = 0
        while i < n:
            if used[i]:
                i += 1
                continue
            t0 = grp.loc[i, "start_time"]
            members = [i]
            j = i + 1
            while j < n and (grp.loc[j, "start_time"] - t0) <= STUTTER_SIG_WINDOW_S:
                if not used[j]:
                    members.append(j)
                j += 1
            sub = grp.loc[members]
            sigs = sorted(sub["signal"].unique())
            if len(sigs) >= STUTTER_SIG_MIN_SIGNALS:
                for m in members:
                    used[m] = True
                rows.append({
                    "rom_rev": grp.loc[i, "rom_rev"],
                    "log_path": log_path,
                    "start_time": round(float(t0), 2),
                    "n_events": len(members),
                    "n_signals": len(sigs),
                    "signal_set": "+".join(sigs),
                    "dominant_signal": grp.loc[i, "signal"],
                    "rpm_mean": sub["rpm_at_event"].mean(),
                    "load_mean": sub["load_at_event"].mean(),
                    "app_mean": sub["accelerator_at_event"].mean(),
                    "throttle_mean": sub["throttle_at_event"].mean(),
                })
                i = j
            else:
                i += 1
    out = pd.DataFrame(rows, columns=OUT_COLUMNS)
    out["_k"] = out["rom_rev"].map(
        lambda r: REV_ORDER.index(r) if r in REV_ORDER else 999)
    out = out.sort_values(["_k", "log_path", "start_time"]).drop(columns="_k")
    return out.reset_index(drop=True)


def main() -> None:
    src = TRENDS_DIR / "stutter_events.csv"
    out_path = TRENDS_DIR / "stutter_clusters.csv"
    ev = pd.read_csv(src, dtype={"rom_rev": str})
    clusters = build_clusters(ev)
    clusters.to_csv(out_path, index=False)
    print(f"Wrote {out_path}")
    print(f"  {len(clusters)} clusters from {len(ev)} events")
    per_rev = clusters["rom_rev"].value_counts()
    for rev in REV_ORDER:
        if rev in per_rev.index:
            print(f"  {rev:>14s}: {int(per_rev[rev])}")


if __name__ == "__main__":
    main()
