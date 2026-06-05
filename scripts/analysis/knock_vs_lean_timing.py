"""
6-3 20.17 — Do knock-fires sit ON lean events, or in their aftermath?
And is the mixture actually lean AT the knock instant (i.e. can tip-in touch it)?

Channels:
  FFB  = commanded AFR (target)
  wbo2 = aftermarket wideband, FAST (responds first)
  AFR  = second AF channel, LAGGED + clamps lean at 20.33  (measured below)

Build a best-estimate 'actual AFR' = wbo2 (fast), cross-checked by lag-aligned AFR.
For each FBKC down-step (true knock-fire), measure:
  - time of the wbo2 lean PEAK in the run-up (the acute lean)
  - gap (knock_time - lean_peak_time)
  - mixture AT the knock instant: wbo2 - FFB  (>0 lean, <0 rich)
"""
import pandas as pd, numpy as np
df=pd.read_csv('logs/6-3 20.17/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df=df[df.time>1].reset_index(drop=True)

# ---- 1. measure AFR-vs-wbo2 lag by cross-correlation over throttle stabs ----
df['accr']=df.Accelerator.diff()/df.time.diff()
stabmask=df.accr>40
best=[]
for lag in range(0,16):
    # how well does AFR(t) match wbo2(t-lag) during/after stabs?
    a=df.AFR.values; w=np.roll(df.wbo2.values,lag)
    sel=stabmask.values.copy(); sel[:16]=False
    c=np.corrcoef(a[sel], w[sel])[0,1]
    best.append((lag,c))
bl=max(best,key=lambda x:x[1])
print("AFR-vs-wbo2 lag scan (corr of AFR(t) with wbo2 shifted back):")
print("  "+"  ".join(f'{l}:{c:.2f}' for l,c in best[:11]))
print(f"  -> AFR lags wbo2 by ~{bl[0]} samples = {bl[0]*0.04:.2f}s (peak corr {bl[1]:.2f})")

# ---- 2. composite 'actual AFR' = wbo2 (fast); AFR_aligned = AFR pulled back by lag ----
df['AFR_alg']=df.AFR.shift(-bl[0])
df['act']=df.wbo2                       # primary estimate
df['lean']=df.act-df.FFB               # +lean / -rich vs commanded

# ---- 3. per knock-fire timing ----
df['dfbkc']=df.FBKC.diff(); df['rdt']=df.time.diff()
fire=df[(df.dfbkc<=-0.3)&(df.rdt<1)]
print(f"\n{'t_knock':>9}{'RPM':>5}{'load':>5}{'leanpeak':>9}{'t_leanpk':>9}{'gap_s':>7}{'wbo2@kn':>8}{'FFB@kn':>7}{'lean@kn':>8}{'state@knock':>13}")
rows=[]
for i in fire.index:
    look=df.loc[max(0,i-40):i+2]
    lp_i=look.lean.idxmax(); lp=look.lean.max(); t_lp=df.loc[lp_i,'time']
    tk=df.loc[i,'time']
    w_kn=df.loc[i,'wbo2']; f_kn=df.loc[i,'FFB']; l_kn=w_kn-f_kn
    state = 'LEAN' if l_kn>0.5 else ('rich' if l_kn<-0.5 else 'at-cmd')
    rows.append(dict(t=tk,lean_kn=l_kn,gap=tk-t_lp,leanpk=lp))
    print(f"{tk:>9.1f}{df.loc[i,'RPM']:>5.0f}{df.loc[i,'load']:>5.2f}{lp:>9.1f}{t_lp:>9.1f}{tk-t_lp:>7.2f}{w_kn:>8.1f}{f_kn:>7.1f}{l_kn:>+8.1f}{state:>13}")
r=pd.DataFrame(rows)
print(f"\nknock-fires where mixture is LEAN at the knock instant:  {(r.lean_kn>0.5).sum()}/{len(r)}")
print(f"knock-fires where mixture is RICH/at-cmd at knock instant: {(r.lean_kn<=0.5).sum()}/{len(r)}")
print(f"median gap from acute-lean PEAK to knock: {r.gap.median():.2f}s  (positive = knock AFTER lean)")
print(f"  (acute lean peaks {r.leanpk.median():.1f} AFR; but at knock the mixture is {r.lean_kn.median():+.1f} vs cmd)")
