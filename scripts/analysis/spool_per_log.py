#!/usr/bin/env python3
"""
Per-log spool rollup -> trends/spool_per_log.csv

Reduces pull_ramps.csv (one row per APP>=30 throttle event) to one row per
log x entry_condition: median time from pedal-on to peak mrp for IN-BAND
pulls (pedal_on_RPM 2000-3500 — the midrange area-under-curve band), plus
median peak mrp and attainment. Entry-condition split is mandatory per
feedback_pull_ramp_compare_method: pre-spooled entries halve time-to-peak
with no ROM change, so never compare across conditions.

Purpose (added 2026-07-16): price spool/response costs of cam & boost work
(first client: the 20.18a AVCS carve's earlier-IVC filling loss) as a
running per-log series instead of ad-hoc pull archaeology.

Reads ONLY the trends store (cheap — no log files). Full regen each run:
    python3 scripts/analysis/spool_per_log.py
"""
from pathlib import Path

import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
TRENDS_DIR = SCRIPT_DIR / "trends"
OUT = TRENDS_DIR / "spool_per_log.csv"

RPM_LO, RPM_HI = 2000, 3500
MIN_PULLS = 3


def main() -> None:
    pr = pd.read_csv(TRENDS_DIR / "pull_ramps.csv")
    m = pr["pedal_on_RPM"].between(RPM_LO, RPM_HI) & pr["time_pedal_to_peak"].notna()
    pr = pr[m]
    rows = []
    for (date, rev, lp, cond), g in pr.groupby(
            ["log_date", "rom_rev", "log_path", "entry_condition"]):
        if len(g) < MIN_PULLS:
            continue
        rows.append(dict(
            log_date=date, rom_rev=rev, log_path=lp, entry_condition=cond,
            n_pulls=int(len(g)),
            t_to_peak_med_s=round(float(g["time_pedal_to_peak"].median()), 3),
            peak_mrp_med=round(float(g["peak_mrp"].median()), 2),
            attainment_med=round(float(g["target_attainment"].median()), 3),
            knock_during=int(g["knock_during"].fillna(0).astype(float).gt(0).sum()),
        ))
    out = pd.DataFrame(rows).sort_values(["log_date", "log_path", "entry_condition"])
    out.to_csv(OUT, index=False)
    print(f"wrote {OUT} ({len(out)} rows)")
    with pd.option_context("display.width", 200):
        print(out.tail(8).to_string(index=False))


if __name__ == "__main__":
    main()
