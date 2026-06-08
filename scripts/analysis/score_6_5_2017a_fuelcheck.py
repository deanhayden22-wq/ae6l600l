"""
Confirm the 20.17a tip-in lift actually DELIVERED fuel (else G1 'lean unchanged'
is a null test, not evidence). Split cusp stab-lean into DFCO-recovery vs real.
"""
import pandas as pd, numpy as np
df=pd.read_csv('logs/6-5 20.17a/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df=df[df.time>1].reset_index(drop=True)
df['be']=df.Trgt_Boost-df.mrp
df['accr']=df.Accelerator.diff()/df.time.diff()
df['lean']=df.wbo2-df.FFB

ons=df.index[(df.accr>40)&(df.accr.shift(1)<=40)]
rows=[]
for i in ons:
    win=df.loc[i:i+15]
    if not ((win.RPM.between(1600,3000))&(win.load.between(1.0,1.25))).any(): continue
    pre=df.loc[max(0,i-25):i]           # 1s before stab
    dfco = pre.IPW.min()==0             # was fuel cut just before?
    ipw_pre=df.loc[max(0,i-3):i,'IPW'].min()
    ipw_post=win.IPW.max()
    rows.append(dict(t=df.loc[i,'time'], be=df.loc[i,'be'],
                     ipw_jump=ipw_post-ipw_pre, ipw_post=ipw_post,
                     lean=(win.wbo2-win.FFB).max(), dfco=dfco))
t=pd.DataFrame(rows)
print(f"in-zone cusp stabs: {len(t)}  | DFCO-recovery {t.dfco.sum()}  real(non-DFCO) {(~t.dfco).sum()}")
print(f"\n  tip-in IS firing?  median IPW jump at stab = {t.ipw_jump.median():.2f} ms "
      f"(post {t.ipw_post.median():.2f} ms) -> {'YES, fuel delivered' if t.ipw_jump.median()>0.3 else 'NO/weak'}")
print(f"  median BE at stab = {t.be.median():.2f} psi (BE-comp axis input; lift targeted 0.9-2.8 psi)\n")
print(f"  stab-lean ALL          : median {t.lean.median():.2f} AFR  (G1 = this, 2.08)")
print(f"  stab-lean DFCO-recovery : median {t[t.dfco].lean.median():.2f} AFR  (wbo2 climbing out of fuel-cut, NOT fixable by tip-in)")
print(f"  stab-lean REAL non-DFCO : median {t[~t.dfco].lean.median():.2f} AFR  (the part tip-in fuel SHOULD fix)")
print(f"\n  -> if REAL non-DFCO lean is still ~2 AFR despite tip-in firing {t.ipw_jump.median():.1f}ms more,")
print(f"     the cusp lean is NOT a tip-in fuel deficit (wall-wetting / sensor-lag, not deliverable-fuel).")
