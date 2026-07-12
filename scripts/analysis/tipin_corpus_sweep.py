"""
Corpus-wide tip-in lean-event sweep.

Applies the canonical tip-in metric uniformly across every rev-mapped log so we
can see the longitudinal trajectory of tip-in lean, AND splits each event by
entry condition (DFCO/coast-resume vs fueled-state stab) -- the decisive cut
that the legacy single-number metric never made.

Event definition (matches the 20.14->20.15 metric lineage):
  - OL (CL/OL==10), RPM>1200, Throttle>8, wbo2 in [13,19.5], FFB in [10,16]
  - lean = wbo2 - FFB >= 2.0 AFR ; throttle ramping (3-sample delta > 1.5%)
  - contiguous run >= 2 samples (~80ms+)
  - dfco_entry: AFR>=20.0 (fuel-cut flag 20.327) in the ~0.5s before the ramp

Caveats: wbo2 not lag-shifted (matches legacy metric for comparability; lag
shifts event timing not peak magnitude). Coverage differs per log -> report n,
per-min, RPM band, and DFCO split so confounds are visible.
"""
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(".")
revmap = pd.read_csv(ROOT / "logs" / "rom_rev_map.csv")
NEED = ["wbo2", "FFB", "Throttle", "RPM", "CL/OL", "FBKC"]
order = ["stock","20.7","20.8","20.9","20.10","20.11","20.12","20.13","20.14","20.15","20.16","20.17","20.17a","20.18"]

def sweep_log(path):
    try:
        d = pd.read_csv(path, low_memory=False)
    except Exception as e:
        return None, f"read-fail: {e}"
    if not all(c in d.columns for c in NEED):
        return None, "missing cols: " + str([c for c in NEED if c not in d.columns])
    for c in d.columns:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    if "sample" in d.columns:
        d = d.sort_values("sample").reset_index(drop=True)
    hz = 25.0; dt = 1.0 / hz
    d["t3"] = d["Throttle"].diff().rolling(3, min_periods=1).sum()
    d["lean"] = d["wbo2"] - d["FFB"]
    inw = ((d["RPM"] > 1200) & (d["CL/OL"] == 10) & (d["Throttle"] > 8)
           & (d["wbo2"].between(13, 19.5)) & (d["FFB"].between(10, 16)))
    ramp = inw & (d["t3"] > 1.5)
    ramp_min = ramp.sum() * dt / 60.0
    mask = (ramp & (d["lean"] >= 2.0)).to_numpy()
    afr = d["AFR"].to_numpy() if "AFR" in d.columns else np.full(len(d), np.nan)
    ln = d["lean"].to_numpy(); rpm = d["RPM"].to_numpy(); thr = d["Throttle"].to_numpy()
    fbkc = d["FBKC"].to_numpy()
    events = []; i = 0
    while i < len(mask):
        if mask[i]:
            j = i
            while j < len(mask) and mask[j]:
                j += 1
            a2 = max(0, i - 5); b2 = min(len(d) - 1, j - 1 + 5)
            pre = afr[max(0, i - 12):i]
            fb = np.nanmin(fbkc[j - 1:min(len(d), j - 1 + int(2 * hz))]) if j < len(d) else 0.0
            events.append({
                "rpm": float(rpm[i]),
                "lean_peak": float(np.nanmax(ln[a2:b2 + 1])),
                "throttle_step": float(np.nanmax(thr[a2:b2 + 1]) - thr[i]),
                "fbkc_2s": float(fb),
                "dfco_entry": bool(np.nanmax(pre) >= 20.0) if pre.size else False,
            })
            i = j
        else:
            i += 1
    return {"ramp_min": ramp_min, "ev": pd.DataFrame(events)}, None

rows = []; ev_all = []
for _, r in revmap.iterrows():
    rev = r["rom_rev"]; lp = ROOT / "logs" / r["log_path"]
    if not lp.exists():
        continue
    res, err = sweep_log(lp)
    if err:
        print(f"SKIP {rev:12s} {r['log_path']}: {err}"); continue
    ev = res["ev"]; n = len(ev)
    rows.append({"rom_rev": rev, "log": r["log_path"], "ramp_min": res["ramp_min"],
                 "n": n, "med_lean": ev["lean_peak"].median() if n else np.nan,
                 "fbkc_follow": int((ev["fbkc_2s"] < 0).sum()) if n else 0})
    if n:
        ev["rom_rev"] = rev; ev_all.append(ev)

out = pd.DataFrame(rows)
allev = pd.concat(ev_all, ignore_index=True)

print("\n=== PER-LOG ===")
with pd.option_context("display.float_format", "{:.2f}".format, "display.width", 220):
    print(out.to_string(index=False))

print("\n=== ENTRY-CONDITION SPLIT x REV (median lean peak) ===")
sr = []
for rev in order:
    g = allev[allev.rom_rev == rev]
    if not len(g):
        continue
    dfc = g[g.dfco_entry]; fue = g[~g.dfco_entry]
    sr.append({"rom_rev": rev, "n_total": len(g), "pct_dfco": g["dfco_entry"].mean() * 100,
               "n_dfco": len(dfc), "med_dfco": dfc["lean_peak"].median() if len(dfc) else np.nan,
               "n_fueled": len(fue), "med_fueled": fue["lean_peak"].median() if len(fue) else np.nan})
split = pd.DataFrame(sr)
with pd.option_context("display.float_format", "{:.2f}".format, "display.width", 220):
    print(split.to_string(index=False))

print("\n=== FUELED-ONLY median lean by RPM band x rev ===")
fu = allev[~allev.dfco_entry].copy()
fu["band"] = pd.cut(fu["rpm"], [1200,1800,2400,3000,3600,4500,6500])
piv = fu.pivot_table(index="rom_rev", columns="band", values="lean_peak", aggfunc="median", observed=True)
piv = piv.reindex([r for r in order if r in piv.index])
with pd.option_context("display.float_format", "{:.2f}".format, "display.width", 220):
    print(piv.to_string())

split.to_csv("scripts/analysis/trends/tipin_entry_split.csv", index=False)
out.to_csv("scripts/analysis/trends/tipin_per_log.csv", index=False)

try:
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    x = list(range(len(split)))
    fig, ax = plt.subplots(figsize=(11, 5.5))
    ax.plot(x, split["med_dfco"], "o-", color="#c0392b", label="DFCO/coast-resume (wideband artifact)")
    ax.plot(x, split["med_fueled"], "o-", color="#2980b9", label="Fueled-state stab (real tip-in target)")
    ax.axhline(2.0, ls="--", lw=0.8, color="gray")
    for i, rr in split.iterrows():
        if not np.isnan(rr["med_fueled"]):
            ax.annotate(f"n={rr['n_fueled']}", (i, rr["med_fueled"]), textcoords="offset points",
                        xytext=(0, -13), ha="center", fontsize=7, color="#2980b9")
    ax.set_xticks(x); ax.set_xticklabels(split["rom_rev"], rotation=45)
    ax.set_ylabel("Median tip-in lean peak  (wbo2 - FFB, AFR)")
    ax.set_title("Tip-in lean across the build, split by entry condition\nDFCO-recovery events are a flat artifact; fueled-state tip-in is the real target")
    ax.legend(); ax.grid(alpha=0.3); fig.tight_layout()
    fig.savefig("scripts/analysis/trends/tipin_longitudinal.png", dpi=130)
    print("\nwrote trends/tipin_longitudinal.png + tipin_entry_split.csv + tipin_per_log.csv")
except Exception as e:
    print(f"plot skipped: {e}")
