"""
6-5 20.17a follow-up:
  (A) decode the UNEXPECTED 0xCC4EC change (decel-fuelcut tier boundary / overrun resume)
  (B) find + classify every deep knock event (FBKC <= -3) across the whole log
  (C) cusp residency + context vs the 6-3 20.17 log (apples-to-apples test power)
"""
import sys, struct
import pandas as pd, numpy as np
sys.path.insert(0,'scripts/analysis')
from knock_shift_filter import classify_knock_events

a=open('rom/AE5L600L 20g rev 20.17.bin','rb').read()
b=open('rom/AE5L600L 20g rev 20.17a.bin','rb').read()
print("="*78); print("(A) 0xCC4EC region — what actually changed (3-tier decel-fuelcut classifier)")
print("="*78)
# memory project_overrun_fuelcut_tier_system: 0xCC4EC/F0/F4 = 3 RPM-threshold floats (big-endian)
for off in (0xCC4EC,0xCC4F0,0xCC4F4,0xCC4F8):
    va=struct.unpack('>f',a[off:off+4])[0]; vb=struct.unpack('>f',b[off:off+4])[0]
    tag='' if va==vb else '   <-- CHANGED'
    print(f"  0x{off:05X}:  20.17 {va:10.3f}   ->  20.17a {vb:10.3f}{tag}")
print("  (per memory these are RPM-tier boundaries selecting per-tier cut-counter [38,38,38,6])")

print("\n"+"="*78); print("(B) deep knock events (FBKC <= -3) — whole log, shift-classified")
print("="*78)
df=pd.read_csv('logs/6-5 20.17a/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df=df[df.time>1].reset_index(drop=True)
df['be']=df.Trgt_Boost-df.mrp
df['lean']=df.wbo2-df.FFB
df['accr']=df.Accelerator.diff()/df.time.diff()
df['mph_chg']=df.MPH.diff()
cls=classify_knock_events(df)
shift_idx=set(cls.index[cls['shift_class']=='shift']) if 'shift_class' in cls else set()

deep=df[df.FBKC<=-3]
print(f"samples with FBKC<=-3: {len(deep)}  | whole-log FBKC min {df.FBKC.min():+.2f}")
# group into episodes
idx=deep.index.tolist(); eps=[]
for i in idx:
    if eps and i-eps[-1][-1]<=25: eps[-1].append(i)
    else: eps.append([i])
print(f"deep-knock episodes: {len(eps)}\n")
for ep in eps:
    i0,i1=ep[0],ep[-1]; s=df.loc[i0:i1]
    look=df.loc[max(0,i0-38):i0]
    mn=s.FBKC.min()
    isshift=np.mean([ix in shift_idx for ix in ep])>=0.5
    stab=look.accr.max()>40
    print(f"  t={df.loc[i0,'time']:8.1f}  RPM {s.RPM.min():.0f}-{s.RPM.max():.0f}  load {s.load.median():.2f}  "
          f"mrp {s.mrp.max():.1f}  min FBKC {mn:+.2f}  CL/OL {int(df.loc[i0,'CL/OL'])}  "
          f"{'SHIFT' if isshift else ('STAB' if stab else 'no-stab')}  "
          f"|dMPH/3s| {abs(df.loc[i0,'MPH']-df.loc[max(0,i0-75),'MPH']):.0f}  gear~{s.MPH.median()/s.RPM.median()*1000:.2f}")

# where did 100% throttle / 75% APP happen and what did boost/knock do?
print("\n"+"="*78); print("(C) the WOT-ish moment (max throttle 100, max APP 75) — did it make boost?")
print("="*78)
wot=df[df.Throttle>=90]
print(f"samples throttle>=90%: {len(wot)}  | their mrp: max {wot.mrp.max():.1f} median {wot.mrp.median():.1f} psi"
      f"  RPM {wot.RPM.min():.0f}-{wot.RPM.max():.0f}")
print(f"  -> still NO real boost pull (spring is 15 psi; peak {df.mrp.max():.1f}). Top-end/WOT intent UNTESTED again.")

# cusp residency comparison
print("\n"+"="*78); print("(D) cusp test power — 6-5 20.17a vs 6-3 20.17")
print("="*78)
for tag,path in [('20.17 (6-3)','logs/6-3 20.17/log0001.csv'),('20.17a (6-5)','logs/6-5 20.17a/log0001.csv')]:
    d=pd.read_csv(path); d.columns=[c.strip() for c in d.columns]; d=d[d.time>1]
    cz=d[(d.RPM.between(1600,3000))&(d.load.between(1.0,1.25))]
    print(f"  {tag}: cusp residency {len(cz)*0.04/60:.2f} min ({len(cz)} samp)  "
          f"cusp FBKC min {cz.FBKC.min():+.2f}")
