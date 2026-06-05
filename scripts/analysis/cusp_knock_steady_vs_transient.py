"""
Decisive test for tip-in authority on the ghost-zone cusp (1600-3000 RPM x load 1.0-1.2).

If the cusp knocks ONLY when a stab/lean precedes it -> transient/fuel-bound -> tip-in
(and overrun) can help.  If it ALSO knocks in steady passes (no stab, no lean, load
stable) -> load/timing-bound (ghost zone) -> tip-in cannot save the deep half.

Context per sample (using wbo2 as the trusted actual-AFR channel):
  stab     = max accel-rate in last 1.0s > 40 %/s
  acutelean= max (wbo2 - FFB) in last 1.5s > 3 AFR
  steady   = NOT stab AND NOT acutelean AND |load change over last 1.0s| < 0.15
Compare knock-fire rate (FBKC down-step) per minute of residency in each context.
"""
import pandas as pd, numpy as np
df=pd.read_csv('logs/6-3 20.17/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df=df[df.time>1].reset_index(drop=True)
df['accr']=df.Accelerator.diff()/df.time.diff()
df['lean']=df.wbo2-df.FFB
df['dfbkc']=df.FBKC.diff(); df['rdt']=df.time.diff()
df['fire']=(df.dfbkc<=-0.3)&(df.rdt<1)

# rolling context (windows in samples @25Hz)
df['stab']    = df.accr.rolling(25,min_periods=1).max()>40
df['acutelean']= df.lean.rolling(38,min_periods=1).max()>3
df['loadchg'] = (df.load - df.load.shift(25)).abs()
df['steady']  = (~df.stab)&(~df.acutelean)&(df.loadchg<0.15)

cusp = df[(df.RPM.between(1600,3000))&(df.load.between(1.00,1.25))].copy()
dt=0.04
def rate(sub,label):
    n=len(sub); mins=n*dt/60; fires=int(sub.fire.sum())
    print(f"  {label:<28} residency {mins:6.2f} min ({n:6d} samp)   knock-fires {fires:3d}   rate {fires/mins if mins else 0:6.2f}/min")
    return fires,mins

print(f"=== CUSP cells 1600-3000 x load 1.00-1.25 :  {len(cusp)} samples, {len(cusp)*dt/60:.1f} min residency ===")
print(f"total knock-fires in cusp: {int(cusp.fire.sum())}\n")
rate(cusp[cusp.stab], "TRANSIENT (recent stab)")
rate(cusp[cusp.acutelean & ~cusp.stab], "LEAN-only (no stab)")
rate(cusp[cusp.steady], "STEADY (no stab/lean, load flat)")
rate(cusp[~cusp.stab & ~cusp.acutelean], "non-transient (any load)")

# how many of the 10 fires were in a STEADY context?
print("\n=== context of each knock-fire in the cusp ===")
f=cusp[cusp.fire]
for _,r in f.iterrows():
    ctx='STEADY' if r.steady else ('stab' if r.stab else ('lean-only' if r.acutelean else 'other'))
    print(f"  t={r.time:8.1f} RPM {r.RPM:4.0f} load {r.load:.2f}  ctx={ctx:10s}  lean@now {r.lean:+.1f}  loadchg/1s {r.loadchg:.2f}")

# sanity: how much steady residency did the cusp actually get (can we even see steady knock)?
print(f"\nsteady residency in cusp = {len(cusp[cusp.steady])*dt/60:.2f} min "
      f"({100*len(cusp[cusp.steady])/max(1,len(cusp)):.0f}% of cusp time) -- "
      f"{'enough to detect steady knock' if len(cusp[cusp.steady])>1500 else 'LOW - weak test'}")
