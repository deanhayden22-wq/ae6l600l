#!/usr/bin/env python3
"""
Regeneratable scorecard dashboard.

Reads the live trends store and emits a self-contained HTML file with:
- KPI cards for the active rev (auto-detected as last rev in REV_ORDER
  present in scorecard.csv)
- Per-rev metric trends (line chart)
- Active-rev cluster signal-set distribution + RPM x dominant-signal stack
- AVCS-led cluster table
- ROM changeset for active transition (+ prior, collapsible)
- Knock event map (RPM x load, residency-overlaid)
- MAF residual surface (mafv x mafgs, sample-weighted)

The HTML body/JS lives in scripts/analysis/dashboard_template.html.

ROM changeset depends on scripts/analysis/trends/rom_changeset.json - run
  python3 scripts/analysis/rom_changeset.py
to refresh it after any .bin lands.

Usage:
    python3 scripts/analysis/dashboard.py
    python3 scripts/analysis/dashboard.py --rev 20.11
    python3 scripts/analysis/dashboard.py --out /path/to/dashboard.html
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"
TEMPLATE_PATH = Path(__file__).parent / "dashboard_template.html"
DEFAULT_OUT = REPO_ROOT / "scorecard_dashboard.html"

REV_ORDER = ["old_2023_base", "stock", "20.7", "20.8", "20.9", "20.10", "20.11", "20.12", "20.13"]


def trend_series(sc: pd.DataFrame, thread: str, metric: str, revs: list[str]) -> list:
    out = []
    for r in revs:
        m = sc[(sc["thread"] == thread) & (sc["metric"] == metric) & (sc["rom_rev"] == r)]
        out.append(round(float(m["value"].iloc[0]), 3) if len(m) else None)
    return out


def latest_metric(sc: pd.DataFrame, rev: str, thread: str, metric: str) -> tuple[float, float, float]:
    m = sc[(sc["rom_rev"] == rev) & (sc["thread"] == thread) & (sc["metric"] == metric)]
    if not len(m):
        return (float("nan"),) * 3
    return (
        float(m["value"].iloc[0]),
        float(m["delta_vs_baseline"].iloc[0]) if pd.notna(m["delta_vs_baseline"].iloc[0]) else float("nan"),
        float(m["delta_vs_prior"].iloc[0]) if pd.notna(m["delta_vs_prior"].iloc[0]) else float("nan"),
    )


def _nearest(value: float, grid: list[float]) -> float:
    return min(grid, key=lambda g: abs(g - value))


def build_knock_map(rev: str) -> dict:
    """Per-rev knock heatmap on knock_by_cell axes, with nearest-neighbor
    residency overlay from cell_residency.csv (grids differ - residency is
    a heuristic context overlay, not an exact join)."""
    kc = pd.read_csv(TRENDS_DIR / "knock_by_cell.csv", dtype={"rom_rev": str})
    res = pd.read_csv(TRENDS_DIR / "cell_residency.csv")

    active = kc[kc["rom_rev"] == rev].copy()
    rpm_grid = sorted(kc["rpm_bin"].dropna().unique().tolist())
    load_grid = sorted(kc["load_bin"].dropna().unique().tolist())
    res_rpm = sorted(res["rpm_bp"].unique().tolist())
    res_load = sorted(res["load_bp"].unique().tolist())

    agg = (
        active.groupby(["rpm_bin", "load_bin"], dropna=False)
        .agg(
            n_fbkc=("event_count_fbkc", "sum"),
            n_flkc=("event_count_flkc", "sum"),
        )
        .reset_index()
    )

    res_map = {
        (float(r["rpm_bp"]), float(r["load_bp"])): float(r["active_pct"])
        for _, r in res.iterrows()
    }

    cells = []
    max_events = 0
    for load in load_grid:
        row = []
        for rpm in rpm_grid:
            hit = agg[(agg["rpm_bin"] == rpm) & (agg["load_bin"] == load)]
            n_fbkc = int(hit["n_fbkc"].iloc[0]) if len(hit) else 0
            n_flkc = int(hit["n_flkc"].iloc[0]) if len(hit) else 0
            n_total = n_fbkc + n_flkc
            max_events = max(max_events, n_total)
            r_rpm = _nearest(rpm, res_rpm) if res_rpm else 0
            r_load = _nearest(load, res_load) if res_load else 0
            residency_pct = res_map.get((r_rpm, r_load), 0.0)
            row.append({
                "fbkc": n_fbkc,
                "flkc": n_flkc,
                "n": n_total,
                "res_pct": round(residency_pct, 3),
            })
        cells.append(row)

    return {
        "rev": rev,
        "rpm": rpm_grid,
        "load": load_grid,
        "cells": cells,
        "max_events": int(max_events),
        "n_logs_for_rev": int(active["log_path"].nunique()) if len(active) else 0,
    }


def build_maf_residual(rev: str) -> dict:
    """Per-rev MAF residual heatmap. mean_correction positive = ECU added
    fuel (MAF underreporting / lean); negative = rich."""
    mc = pd.read_csv(TRENDS_DIR / "maf_corr_by_mafcell.csv", dtype={"rom_rev": str})
    active = mc[mc["rom_rev"] == rev].copy()

    mafv_grid = sorted(active["mafv_bin"].dropna().unique().tolist())
    mafgs_grid = sorted(active["mafgs_bin"].dropna().unique().tolist())

    def _w_mean(g):
        sc = g["sample_count"].sum()
        if sc <= 0:
            return pd.Series({"mean_corr": float("nan"), "n": 0})
        return pd.Series({
            "mean_corr": (g["mean_correction"] * g["sample_count"]).sum() / sc,
            "n": int(sc),
        })

    grouped = (
        active.groupby(["mafv_bin", "mafgs_bin"], dropna=False)
        .apply(_w_mean, include_groups=False)
        .reset_index()
    )

    cells = []
    abs_max = 0.0
    for mafgs in mafgs_grid:
        row = []
        for mafv in mafv_grid:
            hit = grouped[(grouped["mafv_bin"] == mafv) & (grouped["mafgs_bin"] == mafgs)]
            if len(hit) and pd.notna(hit["mean_corr"].iloc[0]):
                v = float(hit["mean_corr"].iloc[0])
                n = int(hit["n"].iloc[0])
                abs_max = max(abs_max, abs(v))
                row.append({"v": round(v, 2), "n": n})
            else:
                row.append({"v": None, "n": 0})
        cells.append(row)

    return {
        "rev": rev,
        "mafv": [round(v, 3) for v in mafv_grid],
        "mafgs": [round(v, 2) for v in mafgs_grid],
        "cells": cells,
        "abs_max": round(abs_max, 2),
        "n_cells": sum(1 for row in cells for c in row if c["v"] is not None),
        "n_logs_for_rev": int(active["log_path"].nunique()) if len(active) else 0,
    }


def build_changeset() -> dict:
    path = TRENDS_DIR / "rom_changeset.json"
    if not path.exists():
        return {"transitions": [], "missing": True}
    return json.loads(path.read_text())


def build_data(rev: str) -> dict:
    sc = pd.read_csv(TRENDS_DIR / "scorecard_latest.csv", dtype={"rom_rev": str})
    revs = [r for r in REV_ORDER if r in sc["rom_rev"].values]

    kpi_specs = [
        ("Stutter signature / min", "cross_thread", "stutter_signature_per_min", "lower_is_better"),
        ("Total knock / min", "timing_sum", "total_knock_per_min", "lower_is_better"),
        ("MAF trim |mean| %", "ol_fueling", "maf_corr_mean_abs_pct", "lower_is_better"),
        ("Min FBKC depth (deg)", "timing_sum", "min_fbkc_depth", "higher_is_better"),
    ]
    kpis = []
    for label, t, m, dir_ in kpi_specs:
        v, _, dprior = latest_metric(sc, rev, t, m)
        kpis.append({"label": label, "value": v, "delta_prior": dprior, "dir": dir_})

    trend_metrics = [
        ("stutter signature", "#534AB7", None, "cross_thread", "stutter_signature_per_min"),
        ("throttle hunt",     "#185FA5", [4, 3], "pedal_throttle", "throttle_hunt_per_min"),
        ("AVCS osc",          "#0F6E56", None, "avcs", "avcs_osc_per_min"),
        ("total knock",       "#BA7517", [4, 3], "timing_sum", "total_knock_per_min"),
        ("AFR osc",           "#D85A30", None, "ol_fueling", "afr_osc_per_min"),
        ("FFB-wbo2 div",      "#D4537E", [2, 2], "ol_fueling", "ffb_wbo2_div_per_min"),
    ]
    trends = []
    for label, color, dash, thr, met in trend_metrics:
        trends.append({
            "label": label, "color": color, "dash": dash or [],
            "data": trend_series(sc, thr, met, revs),
        })

    cl = pd.read_csv(TRENDS_DIR / "stutter_clusters.csv", dtype={"rom_rev": str})
    active = cl[cl["rom_rev"] == rev].copy()
    n_clusters = len(active)

    sigset_counts = active["signal_set"].value_counts().head(6)

    def _pretty(s: str) -> str:
        return (s.replace("ffb_wbo2_divergence", "FFB-wbo2")
                  .replace("avcs_oscillation", "AVCS")
                  .replace("rpm_swing_steady_tps", "RPM-swing")
                  .replace("throttle_hunt_at_steady_app", "throttle-hunt")
                  .replace("timing_osc", "timing osc")
                  .replace("afr_osc", "AFR osc")
                  .replace("+", " + "))

    sigset_data = [{"label": _pretty(s), "n": int(n)} for s, n in sigset_counts.items()]

    rpm_bins = [0, 1500, 2000, 2500, 3000, 3500, 4000, 8000]
    rpm_labels = ["<1500", "1500-2000", "2000-2500", "2500-3000", "3000-3500", "3500-4000", "4000+"]
    if n_clusters:
        active["rpm_band"] = pd.cut(active["rpm_mean"], bins=rpm_bins, labels=rpm_labels)
        rpm_x = active.groupby(["rpm_band", "dominant_signal"], observed=True).size().unstack(fill_value=0)
    else:
        rpm_x = pd.DataFrame()
    SIG_COLORS = {
        "ffb_wbo2_divergence": "#D4537E",
        "avcs_oscillation": "#0F6E56",
        "afr_osc": "#D85A30",
        "timing_osc": "#BA7517",
        "throttle_hunt_at_steady_app": "#185FA5",
        "rpm_swing_steady_tps": "#534AB7",
    }
    rpm_stack = []
    if len(rpm_x):
        for sig in rpm_x.columns:
            full = [int(rpm_x.loc[b, sig]) if (b in rpm_x.index) else 0 for b in rpm_labels]
            rpm_stack.append({
                "label": _pretty(sig),
                "color": SIG_COLORS.get(sig, "#888"),
                "data": full,
            })

    avcs_led = active[active["signal_set"].str.contains("avcs_oscillation", na=False)].copy()
    avcs_led = avcs_led.sort_values("rpm_mean")
    avcs_rows = []
    for _, r in avcs_led.iterrows():
        avcs_rows.append({
            "log": Path(r["log_path"]).name,
            "t": round(float(r["start_time"]), 1),
            "n": int(r["n_events"]),
            "rpm": int(round(r["rpm_mean"])),
            "load": round(float(r["load_mean"]), 2),
            "app": round(float(r["app_mean"]), 1),
            "sigs": _pretty(r["signal_set"]),
        })

    knock_map = build_knock_map(rev)
    maf_residual = build_maf_residual(rev)
    changeset = build_changeset()
    active_transition = None
    for t in changeset.get("transitions", []):
        if t["after_rev"] == rev:
            active_transition = t
            break

    return {
        "rev": rev,
        "revs": revs,
        "kpis": kpis,
        "trends": trends,
        "n_clusters": n_clusters,
        "n_avcs_clusters": len(avcs_led),
        "sigset_data": sigset_data,
        "rpm_labels": rpm_labels,
        "rpm_stack": rpm_stack,
        "avcs_rows": avcs_rows,
        "knock_map": knock_map,
        "maf_residual": maf_residual,
        "changeset": changeset,
        "active_transition": active_transition,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", help="active rev (default: latest in REV_ORDER present in scorecard)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    sc = pd.read_csv(TRENDS_DIR / "scorecard_latest.csv", dtype={"rom_rev": str})
    revs_present = [r for r in REV_ORDER if r in sc["rom_rev"].values]
    active = args.rev or (revs_present[-1] if revs_present else None)
    if not active:
        raise SystemExit("no revs found in scorecard")

    data = build_data(active)
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    html = (template
            .replace("__REV__", active)
            .replace("__TS__", data["generated_at"])
            .replace("__DATA__", json.dumps(data)))
    out = Path(args.out)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out}")
    print(f"  active rev: {active}")
    print(f"  clusters: {data['n_clusters']} ({data['n_avcs_clusters']} AVCS-led)")
    if data["active_transition"]:
        t = data["active_transition"]
        print(f"  ROM diff {t['before_rev']} -> {t['after_rev']}: {t['n_diff_bytes']} bytes in {t['n_runs']} runs")
    km = data["knock_map"]
    print(f"  knock map: {len(km['rpm'])}x{len(km['load'])} grid, max {km['max_events']} events, {km['n_logs_for_rev']} logs")
    mr = data["maf_residual"]
    print(f"  MAF residual: {mr['n_cells']} cells, +/-{mr['abs_max']}%, {mr['n_logs_for_rev']} logs")


if __name__ == "__main__":
    main()
