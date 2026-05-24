"""
Boost Error residency analysis for tip-in BE comp curve reshape.

Goals:
  1. Where does BE actually live across the drive? (residency by psi bucket)
  2. What does BE look like at LEAN events (where we want tip-in to fire MORE)?
  3. What does BE look like at steady CRUISE (where we want it to STAY attenuated)?
  4. What does BE look like during NORMAL throttle activity (most common case)?

Output informs: which BE psi cells should be loosened, which should be left.
"""
from pathlib import Path
import numpy as np
import pandas as pd

d = pd.read_csv("logs/5-23 20.14/log0003.csv")
for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
d = d.sort_values("sample").reset_index(drop=True)
d["BE_psi"] = d["Trgt_Boost"] - d["mrp"]
d["throttle_d_3"] = d["Throttle"].diff().rolling(3, min_periods=1).sum()
d["lean"] = d["wbo2"] - d["FFB"]

# context masks
running    = (d["RPM"] > 1000) & (d["IPW"] > 0)  # not DFCO
in_OL      = d["CL/OL"] == 10
in_CL      = d["CL/OL"] == 8
opening    = d["throttle_d_3"] > 1.5    # actively opening throttle (the tip-in target case)
steady     = (d["throttle_d_3"].abs() < 0.5) & (d["Throttle"] > 5)  # holding throttle
lean_event = in_OL & opening & (d["lean"] >= 2.0) & (d["wbo2"].between(13, 19.5))

# BE comp axis breakpoints (from 20.14)
BE_AXIS_PSI = [0.00, 1.24, 2.48, 3.71, 4.95, 6.19, 7.43, 8.66, 9.90]
BE_COMP_CURRENT = [-90.62, -87.50, -81.25, -72.66, -62.50, -50.00, -32.03, -5.47, 0.00]

def bucket(series, edges):
    """Return count in each BE psi bucket."""
    cats = pd.cut(series, bins=edges + [99], right=False, include_lowest=True)
    return cats.value_counts().sort_index()

# Edges: just below each axis bin, finer resolution between
edges = [-2, 0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5, 7.0, 7.5, 8.0, 8.5, 9.0, 9.5, 10.0, 12.0, 15.0]

scenarios = {
    "ALL running (running & not DFCO)": running,
    "OL opening throttle (tip-in target)": running & in_OL & opening,
    "OL steady throttle (tip-in DON'T fire)": running & in_OL & steady,
    "CL opening throttle": running & in_CL & opening,
    "CL steady throttle (cruise)": running & in_CL & steady,
    "LEAN events (where we want fix)": running & lean_event,
}

print(f"Total running samples: {running.sum():,}")
print(f"Log duration: {(d['time'].max()-d['time'].min())/60:.1f} min @ ~18.8 Hz\n")

print(f"## BE psi distribution (residency %) by scenario\n")
hdr = f"  {'BE bucket':>14}  "
for label in scenarios:
    hdr += f"  {label[:20]:>20}"
print(hdr)
print("  " + "-"*(len(hdr)-2))

# build per-scenario percentage distributions
dists = {}
for label, mask in scenarios.items():
    counts = bucket(d.loc[mask, "BE_psi"], edges)
    total = counts.sum()
    dists[label] = counts / total * 100 if total > 0 else counts

# print rows by bucket
for i in range(len(edges)):
    lo = edges[i]
    hi = edges[i+1] if i+1 < len(edges) else "+"
    lbl = f"[{lo:>5.1f},{hi if isinstance(hi,str) else f'{hi:>5.1f}'})"
    row = f"  {lbl:>14}  "
    for label, mask in scenarios.items():
        d_dist = dists[label]
        # find the bucket value
        if i < len(d_dist):
            v = d_dist.iloc[i]
            row += f"  {v:>19.2f}%"
        else:
            row += f"  {'-':>20}"
    print(row)

print(f"\n## Summary stats:")
for label, mask in scenarios.items():
    s = d.loc[mask, "BE_psi"].dropna()
    if len(s) == 0:
        continue
    print(f"  {label}  (n={len(s):,})")
    print(f"    median BE: {s.median():+.2f} psi   |  25%={s.quantile(.25):+.2f}  75%={s.quantile(.75):+.2f}  90%={s.quantile(.9):+.2f}  max={s.max():+.2f}")

# ============== Proposed BE comp curve ==============
# Goal: loosen the 2-7 psi attenuation; keep 0-1 psi attenuated; cap at 0% max
proposals = {
    "current 20.14": BE_COMP_CURRENT,
    "Proposal: mild loosening (peaks at -91% kept; mid range -50% to -10%)":
        [-90.62, -85.00, -70.00, -50.00, -30.00, -15.00, -5.00, 0.00, 0.00],
    "Proposal: stronger loosening (mid range -30% to 0%)":
        [-90.62, -80.00, -60.00, -35.00, -15.00,  -5.00,  0.00, 0.00, 0.00],
}

print(f"\n## Proposed BE comp curves (capped at 0% — no positive)")
print(f"  {'BE psi':>8}  " + "  ".join(f"{name[:35]:>35}" for name in proposals))
for i, be in enumerate(BE_AXIS_PSI):
    row = f"  {be:>7.2f}  "
    for name, curve in proposals.items():
        row += f"  {curve[i]:>+34.2f}%"
    print(row)

# ============== Effect at typical operating points ==============
print(f"\n## Effect: post-comp IPW at typical operating points (2800 RPM cruise, 20% throttle Δ)")
print(f"  Assumes: base table @ 20% Δ = 1.30 ms; RPM comp at 2800 = +71% → ×1.711")
print(f"           ECT comp warm = 0% → ×1.0")
print(f"           IPW activation gate = 1.32 ms (UNCHANGED per Dean)")
base_at_20pct = 1.30
rpm_comp = 1.711

print(f"  {'BE psi':>8}  " + "  ".join(f"{name[:30]:>30}" for name in proposals))
for i, be in enumerate(BE_AXIS_PSI):
    row = f"  {be:>7.2f}  "
    for name, curve in proposals.items():
        be_mult = 1 + curve[i]/100
        final = base_at_20pct * rpm_comp * be_mult
        gate = "✓" if final > 1.32 else "✗"
        row += f"  {final:>27.2f} ms {gate}"
    print(row)

# Also at smaller throttle change (3% Δ, more typical for smooth pedal ramps)
print(f"\n## Same comparison at 3% throttle Δ (typical smooth ramp):")
print(f"  Assumes: base table @ 3% Δ = 0.60 ms; rest same")
base_at_3pct = 0.60
for i, be in enumerate(BE_AXIS_PSI):
    row = f"  {be:>7.2f}  "
    for name, curve in proposals.items():
        be_mult = 1 + curve[i]/100
        final = base_at_3pct * rpm_comp * be_mult
        gate = "✓" if final > 1.32 else "✗"
        row += f"  {final:>27.2f} ms {gate}"
    print(row)
