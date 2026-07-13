#!/usr/bin/env python3
"""
Did the tau changes change anything measurable? (2026-07-12, Dean's ask)

Tau eras (verified from bins same day):
  stock          : axis 2.0/4.0/8.0, warm cols ~0.5-0.6 all rows
  20.8 - 20.17a  : axis 1.4/3.0/8.0, ALL rows cut warm (row1 0.4, rows2-3 0.25-0.35)
  20.18+         : row1 (load 1.4) warm RESTORED to stock; rows 2-3 still cut

Per log, two observables:
 1. LOW-LOAD WARM STABS (row-1 territory, the 20.17a vs 20.18 A/B):
    - enrich_cmd: pre-stab FFB minus min FFB in 1 s window (commanded transient
      enrichment; tau shows up in FFB). PCV leak does NOT confound the command
      side (leak air was unmetered -> command unaffected).
    - stab_lean: peak (wbo2 lag-8 minus FFB) in window (delivered; PCV-confounded
      across the 6-21 boundary).
 2. RISING-LOAD BOOST STACK (rows 2-3 territory, the reason for the cut):
    - stack med/p90 = own-rev OL B Low map minus FFB, on CL/OL==10, mrp>8,
      load>1.5, rising (d(load) 5-sample mean > 0.02). Positive = FFB richer
      than map. Also settled stack (|dload|<=0.005).
Caveats: BE-comp lifted 20.17/17a, tip-in tables raised somewhere pre-20.15,
MAF rescale in 20.18 — cross-era deltas are tau-dominated, not tau-pure.
Resumable: appends to trends/tau_effect_scan.csv, skips logs already done.
"""
from __future__ import annotations
import struct, sys
from pathlib import Path
import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from log_review_ingest import load_log  # noqa: E402
REPO_ROOT = SCRIPT_DIR.parents[1]
OUT = SCRIPT_DIR / "trends" / "tau_effect_scan.csv"

BINS = {
    "stock": "ae5l600l.bin",
    "20.8": "AE5L600L 20g rev 20.8 tiny wrex.bin",
    "20.9": "AE5L600L 20g rev 20.9 tiny wrex.bin",
    "20.10": "AE5L600L 20g rev 20.10 tiny wrex.bin",
    "20.11": "AE5L600L 20g rev 20.11.bin", "20.12": "AE5L600L 20g rev 20.12.bin",
    "20.13": "AE5L600L 20g rev 20.13.bin", "20.14": "AE5L600L 20g rev 20.14.bin",
    "20.15": "AE5L600L 20g rev 20.15.bin", "20.16": "AE5L600L 20g rev 20.16.bin",
    "20.17": "AE5L600L 20g rev 20.17.bin", "20.17a": "AE5L600L 20g rev 20.17a.bin",
    "20.18": "AE5L600L 20g rev 20.18.bin",
}

def ol_map(rev):
    p = REPO_ROOT / "rom" / BINS[rev]
    b = open(p, "rb").read()
    la = np.array(struct.unpack_from(">17f", b, 0xd01b8))
    ra = np.array(struct.unpack_from(">18f", b, 0xd01fc))
    raw = np.array(struct.unpack_from(f">{18*17}B", b, 0xd0244)).reshape(18, 17)
    return la, ra, 14.7 / (1 + raw * 0.0078125)

def interp(la, ra, tab, l, r):
    li = np.clip(np.searchsorted(la, l) - 1, 0, 15); ri = np.clip(np.searchsorted(ra, r) - 1, 0, 16)
    lf = np.clip((l - la[li]) / (la[li + 1] - la[li]), 0, 1)
    rf = np.clip((r - ra[ri]) / (ra[ri + 1] - ra[ri]), 0, 1)
    return tab[ri, li]*(1-lf)*(1-rf) + tab[ri, li+1]*lf*(1-rf) + tab[ri+1, li]*(1-lf)*rf + tab[ri+1, li+1]*lf*rf

def one(path, rev, date):
    df = load_log(path)
    need = {"FFB", "wbo2", "RPM", "load", "Accelerator", "IPW", "mrp", "CL/OL"}
    if not need.issubset(df.columns):
        return None
    warm = df["ECT"] > 170 if "ECT" in df.columns else pd.Series(True, index=df.index)
    app = df["Accelerator"].to_numpy(); n = len(df)
    # --- low-load warm stabs
    jump = np.zeros(n, bool); jump[4:] = (app[4:] - app[:-4]) > 8
    ec, sl = [], []
    i = 0
    while i < n:
        if jump[i] and warm.iat[i] and df["load"].iat[i] < 1.3 and app[max(0, i-13):i].mean() < 20:
            w = df.iloc[i:i+25]
            if len(w) == 25 and (w["IPW"] > 0).all():
                pre = df["FFB"].iloc[max(0, i-13):i].median()
                ec.append(pre - w["FFB"].min())
                wb = df["wbo2"].iloc[i+8:i+33]
                if len(wb) == 25:
                    sl.append((wb.to_numpy() - w["FFB"].to_numpy()).max())
            i += 25
        else:
            i += 1
    # --- rising-load boost stack vs own-rev OL map
    stack_med = stack_p90 = stack_settled = np.nan; n_rise = 0
    if rev in BINS:
        la, ra, tab = ol_map(rev)
        m = (df["CL/OL"] == 10) & (df["mrp"] > 8) & (df["load"] > 1.5)
        if m.sum() >= 20:
            d = df[m]
            cmd = interp(la, ra, tab, d["load"].to_numpy(), d["RPM"].to_numpy())
            st = cmd - d["FFB"].to_numpy()
            dl = df["load"].diff().rolling(5).mean()[m].to_numpy()
            rise = dl > 0.02; sett = np.abs(dl) <= 0.005
            n_rise = int(rise.sum())
            if n_rise >= 10:
                stack_med = float(np.median(st[rise])); stack_p90 = float(np.quantile(st[rise], .9))
            if sett.sum() >= 10:
                stack_settled = float(np.median(st[sett]))
    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    return dict(log_date=date, rom_rev=rev, log_path=rel,
                n_stabs=len(ec),
                enrich_cmd_med=round(float(np.median(ec)), 3) if len(ec) >= 10 else np.nan,
                stab_lean_med=round(float(np.median(sl)), 2) if len(sl) >= 10 else np.nan,
                n_rise=n_rise, stack_rise_med=round(stack_med, 3) if stack_med == stack_med else np.nan,
                stack_rise_p90=round(stack_p90, 3) if stack_p90 == stack_p90 else np.nan,
                stack_settled_med=round(stack_settled, 3) if stack_settled == stack_settled else np.nan)

def main():
    m = pd.read_csv(REPO_ROOT / "logs" / "rom_rev_map.csv")
    done = set()
    rows = []
    if OUT.exists():
        prev = pd.read_csv(OUT); rows = prev.to_dict("records"); done = set(prev["log_path"])
    budget = 6  # logs per invocation (resumable)
    for _, r in m.iterrows():
        if budget == 0:
            break
        p = REPO_ROOT / "logs" / r["log_path"]
        rel = f"logs/{r['log_path']}"
        if rel in done or not p.exists():
            continue
        try:
            row = one(p, str(r["rom_rev"]), str(r["log_date"]))
        except Exception as e:
            print(f"ERR {rel}: {e}"); continue
        if row:
            rows.append(row)
            print(f"{row['log_date']} {row['rom_rev']:>7s} stabs={row['n_stabs']:4d} "
                  f"enrich={row['enrich_cmd_med']} lean={row['stab_lean_med']} "
                  f"riseN={row['n_rise']} stack={row['stack_rise_med']}")
        done.add(rel); budget -= 1
    pd.DataFrame(rows).to_csv(OUT, index=False)
    remaining = sum(1 for _, r in m.iterrows()
                    if f"logs/{r['log_path']}" not in done and (REPO_ROOT/"logs"/r["log_path"]).exists())
    print(f"wrote {OUT} ({len(rows)} rows), remaining {remaining}")

if __name__ == "__main__":
    main()
