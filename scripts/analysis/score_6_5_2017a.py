"""
Ingest + score the 6-5 20.17a verification drive.

20.17a = single-variable test: ONLY the tip-in BE-comp DATA (0xCD14C) low-BE cells
were lifted (defeat the early-stab fuel cut). Score against the pre-drive gates:
  G1 (lean) : median cusp stab-lean (wbo2-FFB) 2.24 -> target < 1.5
  G2 (goal) : fewer cusp transient knock-fires; nothing deeper than -2.8 deg
  G3 (regr) : steady-cruise AFC within +/-1.5%; peak IDC < ~85%; cold tip-in richness

Pre-checks first (do these BEFORE scoring):
  - AVCS post-reflash lockout sanity gate (p95 < ~12 deg = locked out, log unusable)
  - ROM byte-diff 20.17 -> 20.17a must be BE-comp-only (per verify-before-claiming)
"""
import sys, struct
import pandas as pd, numpy as np
sys.path.insert(0, 'scripts/analysis')

LOG = 'logs/6-5 20.17a/log0001.csv'
DT = 0.04; W1 = 25; W15 = 38   # 25Hz windows: 1.0s, 1.5s
comp = lambda b: b * 0.78125 - 100   # ThrottleTip-inEnrichmentCompensation(%) uint8

print("="*78)
print("PRE-CHECK 1 — ROM byte diff  20.17 -> 20.17a  (must be BE-comp-only @ 0xCD14C)")
print("="*78)
a = open('rom/AE5L600L 20g rev 20.17.bin','rb').read()
b = open('rom/AE5L600L 20g rev 20.17a.bin','rb').read()
diffs = [i for i in range(len(a)) if a[i] != b[i]]
# group into runs
runs = []
for i in diffs:
    if runs and i - runs[-1][-1] <= 4: runs[-1].append(i)
    else: runs.append([i])
print(f"changed bytes: {len(diffs)}   runs: {len(runs)}")
KNOWN = {0xCD14C: 'Tip-in BE comp DATA (9 bytes)', 0xFFB88: 'firmware checksum (auto)'}
for r in runs:
    lo, hi = r[0], r[-1]
    label = next((v for k,v in KNOWN.items() if lo <= k+12 and hi >= k-2 and abs(lo-k)<16), '??? UNEXPECTED')
    print(f"  0x{lo:05X}-0x{hi:05X}  ({len(r)} bytes)  {label}")
print("\nBE-comp DATA @ 0xCD14C:")
print(f"  20.17 : {' '.join(f'{x:02X}' for x in a[0xcd14c:0xcd14c+9])}")
print(f"  20.17a: {' '.join(f'{x:02X}' for x in b[0xcd14c:0xcd14c+9])}")
be_ax=[0,0.93,1.86,2.79,3.71,4.64,5.57,6.50,6.73]
print(f"  20.17  comp%: {' '.join(f'{comp(x):+.0f}' for x in a[0xcd14c:0xcd14c+9])}")
print(f"  20.17a comp%: {' '.join(f'{comp(x):+.0f}' for x in b[0xcd14c:0xcd14c+9])}")

# confirm everything else tip-in is untouched
for name, off, n in [('throttle gate 0xCC4A0',0xcc4a0,4),('IPW gate 0xCC4A4',0xcc4a4,4),
                     ('RPM comp 0xCD118',0xcd118,16),('BE axis 0xCD128',0xcd128,36),
                     ('applied-ctr A 0xCD165',0xcd165,16),('applied-ctr B 0xCD175',0xcd175,16)]:
    same = a[off:off+n]==b[off:off+n]
    print(f"  {'OK  ' if same else 'CHG '}{name}: {'unchanged' if same else 'CHANGED!'}")

# ---------------------------------------------------------------------------
df = pd.read_csv(LOG); df.columns=[c.strip() for c in df.columns]
df = df[df.time>1].reset_index(drop=True)
N = len(df)
# robust Hz from positive dt (time is non-monotonic across recording segments)
pdt = df.time.diff(); hz = 1/np.median(pdt[(pdt>0)&(pdt<1)])
print("\n"+"="*78)
print(f"OVERVIEW — {LOG}")
print("="*78)
print(f"samples {N}  | ~{hz:.1f} Hz -> {N/hz/60:.1f} min real drive  "
      f"| segments (dt<=0 breaks): {(pdt<=0).sum()}")
print(f"peak mrp {df.mrp.max():.2f} psi | peak IDC {df.IDC.max():.1f}% | "
      f"max throttle {df.Throttle.max():.0f}% | max APP {df.Accelerator.max():.0f}%")
print(f"IAM range {df.IAM.min():.3f}-{df.IAM.max():.3f} | FLKC min {df.FLKC.min():+.2f} | "
      f"FBKC min {df.FBKC.min():+.2f} | KNOCK_FLAG=1 samples {(df.KNOCK_FLAG==1).sum()}")
print(f"ECT range {df.ECT.min():.0f}-{df.ECT.max():.0f} C | EGT max {df.EGT.max():.0f}")

print("\n"+"="*78)
print("PRE-CHECK 2 — AVCS post-reflash lockout sanity gate")
print("="*78)
warm = df[df.RPM>2000]
p95 = warm.avcs.quantile(.95); mx = df.avcs.max()
print(f"AVCS p95 (RPM>2000) = {p95:.1f} deg | whole-log max = {mx:.1f} deg")
for lo,hi in [(1500,2000),(2000,2500),(2500,3000),(3000,3500),(3500,4000)]:
    band = df[df.RPM.between(lo,hi)]
    if len(band): print(f"  {lo}-{hi} RPM: median AVCS {band.avcs.median():.1f} deg  (healthy ~19)")
LOCKED = p95 < 12
print(f"\n  VERDICT: {'*** LOCKED OUT — DATA UNUSABLE ***' if LOCKED else 'AVCS HEALTHY — log is scoreable'}")

# ---------------------------------------------------------------------------
# context channels (match cusp_longitudinal.py exactly)
df['accr']=df.Accelerator.diff()/df.time.diff()
df['rdt']=df.time.diff()
df['lean']=df.wbo2-df.FFB
df['fire']=(df.FBKC.diff()<=-0.3)&(df.rdt<1)
df['stab']=df.accr.rolling(W1,min_periods=1).max()>40
df['acutelean']=df.lean.rolling(W15,min_periods=1).max()>3
df['loadchg']=(df.load-df.load.shift(W1)).abs()
df['steady']=(~df.stab)&(~df.acutelean)&(df.loadchg<0.15)

cz=df[(df.RPM.between(1600,3000))&(df.load.between(1.00,1.25))]
print("\n"+"="*78)
print(f"CUSP 1600-3000 x load 1.00-1.25  —  {len(cz)} samp, {len(cz)*DT/60:.1f} min residency")
print("="*78)

# G1: stab-lean (median peak wbo2-FFB on in-zone stab onsets) — exact cusp_longitudinal method
ons=df.index[(df.accr>40)&(df.accr.shift(1)<=40)]
leans=[]; dfco=0; nons=0
for i in ons:
    win=df.loc[i:i+15]
    if not ((win.RPM.between(1600,3000))&(win.load.between(1.0,1.25))).any(): continue
    nons+=1; leans.append((win.wbo2-win.FFB).max())
    if df.loc[max(0,i-25):i,'IPW'].min()==0: dfco+=1
g1 = np.median(leans) if leans else float('nan')
print(f"\nG1  cusp stab-lean (median peak wbo2-FFB on {nons} in-zone stabs): {g1:.2f} AFR")
print(f"    baseline 20.17 = 2.24  | target < 1.5  | {'PASS' if g1<1.5 else 'FAIL' if g1>=2.0 else 'MARGINAL'}")
print(f"    (dfco fraction of those stabs = {dfco/nons*100:.0f}% — high = lean is wbo2 recovering from fuel-cut)")

# G2: knock-fires + depth + transient/steady split
def rate(sub,label):
    n=len(sub); mins=n*DT/60; f=int(sub.fire.sum())
    print(f"    {label:<34} res {mins:6.2f} min   fires {f:3d}   {f/mins if mins else 0:6.2f}/min")
print(f"\nG2  cusp knock-fires: {int(cz.fire.sum())} total  | min FBKC depth {cz.FBKC.min():+.2f} deg")
print(f"    baseline 20.17: 10 fires (~11/min effective), min -2.8  | target: fewer fires, nothing deeper than -2.8")
rate(cz[cz.stab], "TRANSIENT (recent stab)")
rate(cz[cz.acutelean & ~cz.stab], "LEAN-only (no stab)")
rate(cz[cz.steady], "STEADY (no stab/lean, load flat)")
print(f"    cusp FBKC<0 samples/min = {(cz.FBKC<0).sum()*DT/60 / max(1e-9,len(cz)*DT/60):.2f}  (legacy metric)")
if int(cz.fire.sum()):
    print("    each cusp fire:")
    for _,r in cz[cz.fire].iterrows():
        ctx='STEADY' if r.steady else ('stab' if r.stab else ('lean-only' if r.acutelean else 'other'))
        print(f"      t={r.time:8.1f} RPM {r.RPM:4.0f} load {r.load:.2f} depth {df.loc[_,'FBKC']-df.loc[max(0,_-1),'FBKC']:+.2f} ctx={ctx} lean@now {r.lean:+.1f}")

# G3: steady-cruise AFC + IDC + cold tip-in richness
print("\n"+"="*78); print("G3  regression checks"); print("="*78)
cruise = df[(df['CL/OL']==8)&(df.RPM>=1200)&(df.accr.abs()<3)&(df.load.between(0.3,1.0))]
print(f"G3a steady-cruise AFC (CL=8, |accr|<3, RPM>=1200, load 0.3-1.0, n={len(cruise)}):")
print(f"    AFC mean {cruise.AFC.mean():+.2f}%  median {cruise.AFC.median():+.2f}%  | target +/-1.5%  "
      f"| {'PASS' if abs(cruise.AFC.mean())<=1.5 else 'WATCH'}")
print(f"    AFL mean {cruise.AFL.mean():+.2f}% (long-term trim drift watch, was -2.34)")
print(f"G3b peak IDC {df.IDC.max():.1f}%  | target < 85%  | {'PASS' if df.IDC.max()<85 else 'WATCH'}")
# cold tip-in richness: tip-ins while ECT cold
cold = df[df.ECT<60]
if len(cold)>50:
    cons=cold.index[(cold.accr>40)]
    crich=[(df.loc[i:i+10].wbo2-df.loc[i:i+10].FFB).min() for i in cons[:200]]
    print(f"G3c cold (ECT<60C) tip-in min lean-of-cmd: median {np.median(crich) if crich else float('nan'):+.2f} AFR "
          f"(negative = rich; watch for over-rich now BE cut is gone)  n={len(crich)}")
else:
    print(f"G3c cold-start: only {len(cold)} samples ECT<60C — little/no cold tip-in to assess")
