"""
Companion to cusp_longitudinal.py — the CAM/TIMING state during cusp stabs, by rev.
Tests the stock anomaly: stock had the leanest stabs yet ZERO transient knock.
Hypothesis: 20.x runs more AVCS advance + less base timing in the cusp, so the same
(or smaller) lean now knocks. Per in-zone stab onset, sample the stab window i..i+15.
"""
import pandas as pd, numpy as np, os
from cusp_longitudinal import REV_LOGS

def proc(path):
    if not os.path.exists(path): return []
    df=pd.read_csv(path); df.columns=[c.strip() for c in df.columns]
    if not {'RPM','load','FBKC','avcs','Timing'}.issubset(df.columns): return []
    df=df[df.time>1].reset_index(drop=True)
    df['accr']=(df.Accelerator if 'Accelerator' in df else df.Throttle).diff()/df.time.diff()
    ons=df.index[(df.accr>40)&(df.accr.shift(1)<=40)]
    recs=[]
    for i in ons:
        win=df.loc[i:i+15]
        inz=(win.RPM.between(1600,3000))&(win.load.between(1.0,1.25))
        if not inz.any(): continue
        wz=win[inz]
        recs.append(dict(
            avcs=wz.avcs.median(), avcs_sweep=win.avcs.max()-win.avcs.min(),
            timing=wz.Timing.median(),
            knocked=(win.FBKC.diff()<=-0.3).any()))
    return recs

print("=== CAM/TIMING during in-zone cusp stabs, by rev ===\n")
print(f"{'rev':<7}{'nstabs':>7}{'avcs_med':>9}{'avcs_sweep':>11}{'timing_med':>11}{'%stabs_knock':>13}")
for rev,logs in REV_LOGS.items():
    R=[]
    for p in logs: R+=proc(p)
    if not R: continue
    d=pd.DataFrame(R)
    print(f"{rev:<7}{len(d):>7}{d.avcs.median():>9.1f}{d.avcs_sweep.median():>11.1f}"
          f"{d.timing.median():>11.1f}{100*d.knocked.mean():>12.0f}%")
print("\navcs_med=median cam advance during in-zone stab; avcs_sweep=cam range across stab;")
print("timing_med=median spark advance; %stabs_knock=fraction of in-zone stabs that fired FBKC.")
