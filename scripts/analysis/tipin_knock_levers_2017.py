"""
6-3 20.17 — Tie tip-in lean to FBKC knock and identify the controlling axis.

For each FBKC<0 *episode* (gap-grouped), reconstruct the onset context in the
~1.5s lookback BEFORE knock fired:
  - peak accelerator rate (was it a throttle stab = tip-in?)
  - boost error BE = Trgt - mrp at the stab (the tip-in BE-comp axis input)
  - RPM / load at knock
  - peak lean-of-command (wbo2 - FFB) before knock (did fuel fall behind?)
  - shift classification (so we don't credit shift transients as tip-in knock)

Then bucket the REAL (load/tip-in) knock by RPM and by BE to see which lever
axis the dangerous events live on.
"""
import sys, pandas as pd, numpy as np
sys.path.insert(0, 'scripts/analysis')
from knock_shift_filter import classify_knock_events

df = pd.read_csv('logs/6-3 20.17/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df = df[df.time>1].reset_index(drop=True)
df['be'] = df.Trgt_Boost - df.mrp
df['acc_rate'] = df.Accelerator.diff()/df.time.diff()
df['lean'] = df.wbo2 - df.FFB

# shift classification on all FBKC<0
cls = classify_knock_events(df)
shift_idx = set(cls.index[cls['shift_class']=='shift'])
print(f"FBKC<0 total {(df.FBKC<0).sum()}  | shift-classified {len(shift_idx)}  "
      f"({100*len(shift_idx)/max(1,(df.FBKC<0).sum()):.0f}%)")

# group FBKC<0 into episodes
def episodes(mask, gap=20):
    idx=df.index[mask].tolist()
    if not idx: return []
    e=[[idx[0]]]
    for i in idx[1:]:
        (e[-1].append(i) if i-e[-1][-1]<=gap else e.append([i]))
    return e

LB=38  # ~1.5s lookback at 25Hz
rows=[]
for ep in episodes(df.FBKC<0):
    s=df.loc[ep]
    i0=ep[0]
    look=df.loc[max(0,i0-LB):i0]
    onset_rpm=s.loc[s.FBKC.idxmin(),'RPM']; onset_load=s.loc[s.FBKC.idxmin(),'load']
    # BE at the moment of peak accel stab in lookback
    stab_i = look.acc_rate.idxmax() if look.acc_rate.notna().any() else i0
    be_at_stab = df.loc[stab_i,'be']
    frac_shift = np.mean([ix in shift_idx for ix in ep])
    rows.append(dict(
        t=df.loc[i0,'time'], rpm=onset_rpm, load=onset_load,
        depth=s.FBKC.min(),
        peak_acc_rate=look.acc_rate.max(),
        be_at_stab=be_at_stab,
        be_at_knock=s.be.median(),
        peak_lean_pre=look.lean.max(),
        is_shift=frac_shift>=0.5,
        clol=int(df.loc[i0,'CL/OL']),
    ))
ev=pd.DataFrame(rows)
print(f"\nFBKC<0 episodes: {len(ev)}   shift-dominated: {ev.is_shift.sum()}   real: {(~ev.is_shift).sum()}")

real=ev[~ev.is_shift].copy()
# tip-in association: a throttle stab (>40%/s) within the 1.5s lookback
real['tipin'] = real.peak_acc_rate>40
print(f"\nof {len(real)} real knock episodes:")
print(f"  preceded by throttle stab (>40%/s in 1.5s):  {real.tipin.sum()}/{len(real)}")
print(f"  with a lean spike >+1.0 AFR before knock:    {(real.peak_lean_pre>1.0).sum()}/{len(real)}")
print(f"  tip-in AND lean spike (the mechanism):       {((real.tipin)&(real.peak_lean_pre>1.0)).sum()}/{len(real)}")

print("\n=== REAL knock episodes bucketed by RPM ===")
real['rpmband']=pd.cut(real.rpm,[0,1800,2100,2500,2900,3500],labels=['<1800','1800-2100','2100-2500','2500-2900','2900-3500'])
print(real.groupby('rpmband',observed=True).agg(
    n=('depth','size'), mindepth=('depth','min'),
    tipin=('tipin','sum'), med_be=('be_at_stab','median'),
    med_lean=('peak_lean_pre','median')).to_string())

print("\n=== REAL knock episodes bucketed by BE-at-stab (the tip-in BE-comp axis input) ===")
real['beband']=pd.cut(real.be_at_stab,[-99,0,1,2,3,4.64,6.73,99],
    labels=['<0','0-1','1-2','2-3','3-4.64','4.64-6.73','>6.73(neutral)'])
print(real.groupby('beband',observed=True).agg(
    n=('depth','size'), mindepth=('depth','min'),
    med_rpm=('rpm','median'), med_lean=('peak_lean_pre','median')).to_string())

print("\n=== worst 15 REAL knock episodes (onset context) ===")
w=real.nsmallest(15,'depth')[['t','rpm','load','depth','peak_acc_rate','be_at_stab','peak_lean_pre','clol']]
print(w.to_string(index=False,float_format=lambda x:f'{x:.2f}'))

# ============================================================================
# LEVER QUANTIFICATION: decode the actual 20.17 tip-in tables and compute the
# net tip-in multiplier (vs base IPW) at each knock-fire onset, plus the
# sensitivity to raising the BoostErr comp at the low-BE cells.
# ============================================================================
import struct
rom=open('rom/AE5L600L 20g rev 20.17.bin','rb').read()
comp=lambda b:b*0.78125-100                       # ThrottleTip-inEnrichmentCompensation(%) uint8
rpm_ax=[0,800,1200,1600,2000,2400,2800,3200,3600,4000,4400,4800,5200,5600,6000,6400]
rpm_cp=[comp(b) for b in rom[0xcd118:0xcd118+16]] # RPM comp  0xCD118
be_ax=[0,0.93,1.86,2.79,3.71,4.64,5.57,6.50,6.73] # BE axis psi  0xCD128 (raw float * .01933677)
be_cp=[comp(b) for b in rom[0xcd14c:0xcd14c+9]]   # BE comp  0xCD14C
rcomp=lambda r: np.interp(r,rpm_ax,rpm_cp)
bcomp=lambda be: be_cp[0] if be<=0 else (0.0 if be>=be_ax[-1] else np.interp(be,be_ax,be_cp))

print("\n=== 20.17 tip-in lever tables (decoded) ===")
print(" RPM comp  :", ' '.join(f'{r}:{c:+.0f}%' for r,c in zip(rpm_ax,rpm_cp) if r<=4000))
print(" BE comp   :", ' '.join(f'{p:.2f}psi:{c:+.0f}%' for p,c in zip(be_ax,be_cp)))
print(f" Gates     : throttle {struct.unpack('>f',rom[0xcc4a0:0xcc4a4])[0]:.2f}% , "
      f"IPW {struct.unpack('>f',rom[0xcc4a4:0xcc4a8])[0]*0.004:.2f}ms")

df['dfbkc']=df.FBKC.diff(); df['rdt']=df.time.diff()
fire=df[(df.dfbkc<=-0.3)&(df.rdt<1)]
print("\n=== net tip-in multiplier (vs base IPW) at each knock-fire onset ===")
print(f'{"t":>8} {"RPM":>5} {"BE":>5} {"RPMc":>6} {"BEc":>6} {"net":>6} | {"BE->-40":>7} {"BE->-20":>7}')
for i in fire.index:
    look=df.loc[max(0,i-38):i]; si=look.acc_rate.idxmax()
    r=df.loc[i,'RPM']; be=df.loc[si,'be']; rc=rcomp(r); bc=bcomp(be)
    net=(1+rc/100)*(1+bc/100)
    print(f'{df.loc[i,"time"]:>8.0f} {r:>5.0f} {be:>5.1f} {rc:>+5.0f}% {bc:>+5.0f}% {net:>5.2f}x | '
          f'{(1+rc/100)*0.60:>6.2f}x {(1+rc/100)*0.80:>6.2f}x')
print("\nReading: BE<~4psi stabs deliver 0.16-0.42x base tip-in (gutted ~80% by BE comp).")
print("Raising BE comp at cells 1-4 (0.93-3.71psi) to -40/-20% lifts net to ~0.8-1.3x = 3-5x more fuel.")
