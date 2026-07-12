"""
DFCO-resume recovery-time sweep across the corpus + stock.

Motivation (Dean, 6-9): with the airflow we've added (turbo/intake/exhaust + tune)
there is more air on a tip-in, and the post-fuel-cut resume enrichment may never
have been resized -> slow recovery from full lean out of DFCO. Measure it.

Metric (combustion frame, lag-corrected):
  - resume edge: IPW 0->>=0.5 with RPM>1500 (overrun) AND a throttle tip-in
    (throttle rises >5% within 10 samples) -> isolates DFCO->stab resumes.
  - airflow_step: max MAF in [resume, +12] minus min MAF in [resume-3, resume].
  - recovery: shift wbo2 EARLIER by L=8 samples (~320ms transport lag) to put it
    in the combustion frame, then count samples from resume until |wbo2-FFB|<=1.0
    AFR and it holds (<=1.5) for 3 samples. x40ms = recovery_ms.
  - rich_ffb: richest (min) commanded AFR in the 8 samples after resume.

Caveats: peak-lean magnitude is lag-poisoned (the raw lean spike is largely the
delayed image of the fuel-cut itself); only the lag-corrected recovery time and
the airflow_step / rich_ffb are trustworthy. MAF g/s not directly comparable
across revs if MAF scaling was retouched -> treat airflow_step cross-rev as
directional, not absolute.
"""
from pathlib import Path
import numpy as np
import pandas as pd

revmap = pd.read_csv("logs/rom_rev_map.csv")
order = ["stock","20.7","20.8","20.9","20.10","20.11","20.12","20.13","20.14","20.15","20.16","20.17","20.17a","20.18"]
NEED = ["wbo2","FFB","Throttle","RPM","IPW","MAF","CL/OL"]
L = 8

def events(path):
    d = pd.read_csv(path, low_memory=False)
    if not all(c in d.columns for c in NEED):
        return []
    for c in d.columns:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    if "sample" in d:
        d = d.sort_values("sample").reset_index(drop=True)
    ipw = d.IPW.to_numpy(); thr = d.Throttle.to_numpy(); rpm = d.RPM.to_numpy()
    maf = d.MAF.to_numpy(); ffb = d.FFB.to_numpy(); wb = d.wbo2.to_numpy()
    wb_al = np.concatenate([wb[L:], np.full(L, np.nan)])
    n = len(d); out = []; i = 1
    while i < n:
        if ipw[i-1] < 0.1 and ipw[i] >= 0.5 and rpm[i] > 1500:
            w = thr[i:min(n, i+10)]
            if w.size and (np.nanmax(w) - thr[i-1]) > 5:
                base = np.nanmin(maf[max(0, i-3):i+1]); pk = np.nanmax(maf[i:min(n, i+12)])
                rec = np.nan; leans = []
                for k in range(i, min(n, i+40)):
                    if not np.isnan(wb_al[k]) and 6 <= ffb[k] <= 16:
                        leans.append(wb_al[k]-ffb[k])
                        if abs(wb_al[k]-ffb[k]) <= 1.0:
                            if all(abs(wb_al[m]-ffb[m]) <= 1.5 for m in range(k, min(n, k+3))
                                   if not np.isnan(wb_al[m])):
                                rec = k - i; break
                out.append({"airflow_step": pk-base, "pk_maf": pk, "recov_samp": rec,
                            "peak_lean": max(leans) if leans else np.nan,
                            "rich_ffb": np.nanmin(ffb[i:min(n, i+8)]), "rpm": rpm[i]})
            i += 8
        else:
            i += 1
    return out

agg = {}
for _, r in revmap.iterrows():
    lp = Path("logs")/r["log_path"]
    if lp.exists():
        agg.setdefault(r["rom_rev"], []).extend(events(lp))

rows = []
print(f"{'rev':7s} {'n':>4s} {'air_step':>8s} {'recov_ms':>8s} {'pk_lean':>7s} {'rich_ffb':>8s} {'%unrec':>6s}")
for rev in order:
    e = agg.get(rev, [])
    if not e:
        continue
    df = pd.DataFrame(e); rec = df.recov_samp.dropna()
    rm = rec.median()*40 if len(rec) else np.nan
    print(f"{rev:7s} {len(df):4d} {df.airflow_step.median():8.1f} {rm:8.0f} "
          f"{df.peak_lean.median():7.2f} {df.rich_ffb.median():8.2f} {df.recov_samp.isna().mean()*100:6.0f}")
    rows.append({"rev": rev, "n": len(df), "air_step": df.airflow_step.median(),
                 "recov_ms": rm, "pk_lean": df.peak_lean.median(),
                 "rich_ffb": df.rich_ffb.median(), "pct_unrec": df.recov_samp.isna().mean()*100})
pd.DataFrame(rows).to_csv("scripts/analysis/trends/dfco_recovery.csv", index=False)
print("\nwrote trends/dfco_recovery.csv")
