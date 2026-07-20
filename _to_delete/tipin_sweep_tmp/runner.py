# Resumable per-log driver for tipin_corpus_sweep (45s-call chunking).
# Reuses sweep_log's exact event definition by importing nothing: copied verbatim.
import sys, time, os
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(".")
TMP = ROOT / "scripts/analysis/trends/.tipin_sweep_tmp"
BUDGET = float(sys.argv[1]) if len(sys.argv) > 1 else 28.0
t0 = time.time()

NEED = ["wbo2", "FFB", "Throttle", "RPM", "CL/OL", "FBKC"]

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

revmap = pd.read_csv(ROOT / "logs" / "rom_rev_map.csv")
prog_p = TMP / "per_log_partial.csv"
done = set()
rows = []
if prog_p.exists():
    prev = pd.read_csv(prog_p)
    rows = prev.to_dict("records")
    done = set(prev["log"])

for k, r in revmap.iterrows():
    lp = ROOT / "logs" / r["log_path"]
    if r["log_path"] in done or not lp.exists():
        continue
    if time.time() - t0 > BUDGET:
        print("BUDGET-STOP"); break
    res, err = sweep_log(lp)
    if err:
        rows.append({"rom_rev": r["rom_rev"], "log": r["log_path"], "ramp_min": np.nan,
                     "n": -1, "med_lean": np.nan, "fbkc_follow": -1})
        print(f"SKIP {r['rom_rev']} {r['log_path']}: {err}")
        pd.DataFrame(rows).to_csv(prog_p, index=False)
        continue
    ev = res["ev"]; n = len(ev)
    rows.append({"rom_rev": r["rom_rev"], "log": r["log_path"], "ramp_min": res["ramp_min"],
                 "n": n, "med_lean": ev["lean_peak"].median() if n else np.nan,
                 "fbkc_follow": int((ev["fbkc_2s"] < 0).sum()) if n else 0})
    if n:
        ev["rom_rev"] = r["rom_rev"]
        ev.to_csv(TMP / f"ev_{k:03d}.csv", index=False)
    pd.DataFrame(rows).to_csv(prog_p, index=False)
    print(f"OK {r['rom_rev']:>12} {r['log_path']} n={n} ({time.time()-t0:.1f}s)")

remaining = [r["log_path"] for _, r in revmap.iterrows()
             if r["log_path"] not in {x["log"] for x in rows} and (ROOT/"logs"/r["log_path"]).exists()]
print(f"REMAINING={len(remaining)}")
