"""Regenerate the embedded JSON payload inside metrics_dashboard.html.

metrics_dashboard.html was originally a session-built artifact with its data
hand-embedded. This script makes it reproducible: it rebuilds the `#data`
<script> payload from the trends store and splices it back into the HTML,
leaving all markup/JS/charts untouched.

Usage:  python3 scripts/analysis/metrics_dashboard_data.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
T = REPO / "scripts" / "analysis" / "trends"
HTML = REPO / "metrics_dashboard.html"
MARK_OPEN = '<script id="data" type="application/json">'
MARK_CLOSE = "</script>"


def jnum(v):
    """JSON-safe scalar: NaN/NaT -> None, numpy -> python."""
    if v is None:
        return None
    if isinstance(v, (np.bool_, bool)):
        return bool(v)
    if isinstance(v, str):
        return v
    try:
        if pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating, float, int)):
        f = float(v)
        return None if np.isnan(f) else f
    return v


def col(df, name):
    return [jnum(v) for v in df[name]] if name in df.columns else [None] * len(df)


def build():
    health = pd.read_csv(T / "log_health.csv", dtype={"rom_rev": str})
    # Canonical order = logs/rom_rev_map.csv row order (chronological as Dean
    # maintains it). Alphabetical log_path sorting gets same-day logs wrong:
    # "8-4 2 20.19c" sorts BEFORE "8-4 20.19c" but is the later drive.
    order = pd.read_csv(REPO / "logs" / "rom_rev_map.csv")["log_path"]
    rank = {f"logs/{p}": i for i, p in enumerate(order)}
    health["_ord"] = health["log_path"].map(rank).fillna(10**6)
    health = health.sort_values(["_ord", "log_date"]).drop(columns="_ord").reset_index(drop=True)
    keys = health["log_path"].tolist()
    n = len(health)

    D = {}
    D["logs"] = {
        "date": col(health, "log_date"),
        "rev": col(health, "rom_rev"),
        "name": [p.replace("logs/", "", 1) for p in keys],
    }

    hcols = [c for c in health.columns if c not in ("log_date", "rom_rev", "log_path")]
    D["health"] = {c: col(health, c) for c in hcols}

    dur = health["duration_min"].to_numpy(dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        D["health"]["fires_per_min_whole"] = [
            jnum(x) for x in np.round(health["fbkc_fires"].to_numpy(float) / dur, 4)]
        D["health"]["deep_per_min_whole"] = [
            jnum(x) for x in np.round(health["fbkc_deep"].to_numpy(float) / dur, 4)]
        D["health"]["flkc_dec_per_min"] = [
            jnum(x) for x in np.round(health["flkc_decrements"].to_numpy(float) / dur, 4)]
        fr = health["fbkc_fires_resume"].to_numpy(float)
        ff = health["fbkc_fires"].to_numpy(float)
        pct = np.where(ff > 0, np.round(100.0 * fr / np.where(ff == 0, np.nan, ff), 2), np.nan)
        D["health"]["fires_resume_pct"] = [jnum(x) for x in pct]

    z = pd.read_csv(T / "zone_fire_rates.csv", dtype={"rom_rev": str})
    D["zones"] = {}
    for zone in ("ghost", "cusp", "rect"):
        sub = z[z.zone == zone].drop_duplicates("log_path").set_index("log_path")
        D["zones"][zone] = {
            f: [jnum(sub[f].get(k)) if k in sub.index else None for k in keys]
            for f in ("residency_min", "fires_per_min", "onsets_per_min", "min_fbkc_in_zone")
        }

    ti = pd.read_csv(T / "tipin_per_log.csv", dtype={"rom_rev": str}).drop_duplicates("log")
    ti = ti.set_index("log")
    bare = D["logs"]["name"]
    D["tipin"] = {f: [jnum(ti[f].get(b)) if b in ti.index else None for b in bare]
                  for f in ("ramp_min", "n", "med_lean", "fbkc_follow")}

    tau = pd.read_csv(T / "tau_effect_scan.csv", dtype={"rom_rev": str}).drop_duplicates("log_path")
    tau = tau.set_index("log_path")
    D["tau"] = {f: [jnum(tau[f].get(k)) if k in tau.index else None for k in keys]
                for f in ("n_stabs", "enrich_cmd_med", "stab_lean_med",
                          "stack_rise_med", "stack_rise_p90", "stack_settled_med")}

    av = pd.read_csv(T / "avcs_holdswater.csv", dtype={"rom_rev": str}).drop_duplicates("log_path")
    av = av.set_index("log_path")
    D["avcsbox"] = {f: [jnum(av[f].get(k)) if k in av.index else None for k in keys]
                    for f in ("cam_at_box_med", "cusp_res_min", "deep_per_min")}

    sp = pd.read_csv(T / "spool_per_log.csv", dtype={"rom_rev": str})
    D["spool"] = {}
    for ec in ("post_dfco", "post_coast", "post_partial"):
        sub = sp[sp.entry_condition == ec].drop_duplicates("log_path").set_index("log_path")
        D["spool"][ec] = {
            f: [jnum(sub[f].get(k)) if k in sub.index else None for k in keys]
            for f in ("t_to_peak_med_s", "peak_mrp_med", "n_pulls")
        }

    sc = pd.read_csv(T / "scorecard_latest.csv", dtype={"rom_rev": str})
    import sys
    sys.path.insert(0, str(T.parent))
    from rev_order import REV_ORDER
    revs = [r for r in REV_ORDER if r in set(sc.rom_rev)]
    D["scorecard"] = {}
    for metric, g in sc.groupby("metric"):
        gg = g.drop_duplicates("rom_rev").set_index("rom_rev")
        D["scorecard"][metric] = {
            "thread": str(g["thread"].iloc[0]),
            "revs": revs,
            "vals": [jnum(round(float(gg["value"].get(r)), 4)) if r in gg.index
                     and pd.notna(gg["value"].get(r)) else None for r in revs],
        }
    D["scorecard_meta"] = {
        "run_ts": str(sc["run_ts"].iloc[0])[:10],
        "baseline": str(sc["baseline"].iloc[0]),
    }

    es = pd.read_csv(T / "tipin_entry_split.csv", dtype={"rom_rev": str}).drop_duplicates("rom_rev")
    es = es.set_index("rom_rev")
    D["entry_split"] = {"rev": revs}
    for f in ("n_total", "pct_dfco", "med_dfco", "med_fueled", "n_fueled"):
        D["entry_split"][f] = [jnum(es[f].get(r)) if r in es.index else None for r in revs]

    df = pd.read_csv(T / "dfco_recovery.csv", dtype={"rev": str}).drop_duplicates("rev")
    df = df.set_index("rev")
    D["dfco"] = {"rev": revs}
    for f in ("n", "air_step", "recov_ms", "pk_lean", "rich_ffb", "pct_unrec"):
        D["dfco"][f] = [jnum(df[f].get(r)) if r in df.index else None for r in revs]

    return D, n


def main():
    D, n = build()
    html = HTML.read_text(encoding="utf-8")
    a = html.index(MARK_OPEN) + len(MARK_OPEN)
    b = html.index(MARK_CLOSE, a)
    payload = json.dumps(D, separators=(",", ":"), allow_nan=False)
    HTML.write_text(html[:a] + payload + html[b:], encoding="utf-8")
    print(f"metrics_dashboard.html payload rebuilt: {n} logs, "
          f"last = {D['logs']['date'][-1]} {D['logs']['name'][-1]}")


if __name__ == "__main__":
    main()
