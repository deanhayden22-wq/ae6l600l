"""
Test: is the logged FLKC trace a readout of the per-cell learned knock map,
or a live response?

Method: bin every sample into its Non-Cruise knock-grid cell (load x RPM,
axes read from rev 20.17 ROM). Then:
  (a) at each FLKC value change, did the RPM-cell or load-cell index also
      change in the same step? (boundary crossing)
  (b) within each visited cell, is FLKC constant? (a static map => yes)

If FLKC changes only at boundary crossings and is constant within a cell,
the trace is reading out a static learned map (no live knock now).
"""
import pandas as pd, numpy as np

df = pd.read_csv(r"C:/Users/Dean/Desktop/Untitled 1.csv")
df.columns = [c.strip() for c in df.columns]

# Non-Cruise knock grid (rev 20.17 ROM)
LOAD = [0.27,0.50,0.65,0.94,1.20,1.44,1.67,1.90,2.13,2.37,2.60,2.83,3.07,3.30,3.53,3.77,4.00]
RPM  = [800,1200,1600,2000,2400,2800,3200,3600,4000,4400,4800,5200,5600,6000,6400,6800,7200,7600]

def cell(val, axis):           # index of nearest lower breakpoint (the cell)
    return int(np.searchsorted(axis, val, side="right") - 1)

df["lc"] = df["load"].apply(lambda v: cell(v, LOAD))
df["rc"] = df["RPM"].apply(lambda v: cell(v, RPM))
df["cell"] = list(zip(df.rc, df.lc))

# (a) FLKC changes vs boundary crossings -----------------------------------
df["flkc_chg"] = df.FLKC.diff().fillna(0) != 0
df["rc_chg"]   = df.rc.diff().fillna(0) != 0
df["lc_chg"]   = df.lc.diff().fillna(0) != 0
df["bound_chg"] = df.rc_chg | df.lc_chg

chg = df[df.flkc_chg]
print("=== Every FLKC change, with the cell move at that sample ===")
print(f"{'t':>8} {'RPM':>5} {'load':>5} {'FLKC':>6}  {'->cell(rpm,load bkpt)':>26}  bndry?")
prev = None
for _, r in chg.iterrows():
    rlo, rhi = RPM[r.rc], (RPM[r.rc+1] if r.rc+1 < len(RPM) else 99999)
    llo = LOAD[r.lc]; lhi = LOAD[r.lc+1] if r.lc+1 < len(LOAD) else 9.99
    tag = []
    if r.rc_chg: tag.append("RPM-cross")
    if r.lc_chg: tag.append("load-cross")
    print(f"{r.time:8.2f} {r.RPM:5.0f} {r['load']:5.2f} {r.FLKC:6.2f}  "
          f"rpm[{rlo}-{rhi}) load[{llo:.2f}-{lhi:.2f})  {'+'.join(tag) if tag else 'NO move'}")

n_chg = len(chg)
n_on_bound = int(chg.bound_chg.sum())
print(f"\nFLKC changes: {n_chg}   on a cell-boundary crossing: {n_on_bound}   "
      f"WITHIN a cell (no move): {n_chg-n_on_bound}")

# (b) FLKC constancy within each visited cell -------------------------------
print("\n=== FLKC value(s) seen in each visited cell (FLKC<0 cells) ===")
g = df.groupby("cell").agg(flkc_vals=("FLKC", lambda s: sorted(s.unique())),
                            n=("FLKC","size"),
                            rpm_lo=("RPM","min"), rpm_hi=("RPM","max"))
multi = 0
for cellk, row in g.iterrows():
    vals = row.flkc_vals
    if min(vals) < 0 or len(vals) > 1:
        rc, lc = cellk
        rlo = RPM[rc]; llo = LOAD[lc]
        flag = "  <-- MULTIPLE values in one cell" if len(vals) > 1 else ""
        if len(vals) > 1: multi += 1
        print(f"  cell rpm>={rlo:<5} load>={llo:<4}: FLKC {vals}  (n={row.n}){flag}")
print(f"\ncells with >1 distinct FLKC value (would imply live change in-cell): {multi}")
