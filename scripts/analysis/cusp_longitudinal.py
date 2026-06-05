"""
Longitudinal history of the CUSP zone (1600-3000 RPM x load 1.00-1.25) — the
transient tip-in knock area — across every rev with a compatible log schema.

For each log, within the cusp:
  - residency (min), knock-fire count (FBKC down-step) + rate/min
  - transient-context vs steady-context knock split (the steady test)
  - min FBKC depth
  - FBKC<0 sample-rate/min (legacy comparable metric)
  - acute lean on in-zone stabs: median peak (wbo2-FFB)
  - DFCO-recovery fraction: in-zone stabs that came out of IPW==0 (fuel cut)
Pooled by rev.
"""
import pandas as pd, numpy as np, os

REV_LOGS = {
 'stock':['logs/Older/3-21.csv','logs/Older/3-30.csv','logs/Older/4-1.csv'],
 '20.7' :['logs/Older/4-11.csv','logs/Older/4-12 big.csv'],
 '20.9' :['logs/April/4-25/4-25 full.csv'],
 '20.10':['logs/April/4-27 20.10/log0001.csv','logs/April/4-27 20.10/log0002.csv',
          'logs/April/4-27 20.10/log0003.csv','logs/5-2/5-2.csv'],
 '20.11':['logs/5-8 20.11/5-8.csv','logs/5-10 20.11/log0003.csv','logs/5-11 20.11/log0001.csv',
          'logs/5-11 20.11/log0002.csv','logs/5-11 20.11/log0003.csv','logs/5-12 20.11/5-12.csv'],
 '20.12':['logs/5-17 20.12/log0002.csv','logs/5-17 20.12/log0003.csv','logs/5-17 20.12/log0004.csv',
          'logs/5-17 20.12/log0005.csv','logs/5-17 20.12/log0006.csv','logs/5-17 20.12/log0007.csv'],
 '20.13':['logs/5-22 20.13/log0001.csv'],
 '20.14':['logs/5-23 20.14/log0001.csv','logs/5-23 20.14/log0002.csv','logs/5-23 20.14/log0003.csv'],
 '20.15':['logs/5-26 20.15/log0001.csv','logs/5-28 20.15/log0001.csv'],   # 5-25 excluded: AVCS lockout
 '20.16':['logs/5-30 20.16/log0001.csv'],
 '20.17':['logs/6-3 20.17/log0001.csv'],
}
DT=0.04; W1=25; W15=38   # 25Hz windows: 1.0s, 1.5s

def proc(path):
    if not os.path.exists(path): return None
    df=pd.read_csv(path); df.columns=[c.strip() for c in df.columns]
    if not {'RPM','load','FBKC'}.issubset(df.columns): return None
    df=df[df.time>1].reset_index(drop=True)
    has_fuel = {'wbo2','FFB'}.issubset(df.columns)
    df['accr']=df.Accelerator.diff()/df.time.diff() if 'Accelerator' in df else df.Throttle.diff()/df.time.diff()
    df['rdt']=df.time.diff()
    df['fire']=(df.FBKC.diff()<=-0.3)&(df.rdt<1)
    df['stab']=df.accr.rolling(W1,min_periods=1).max()>40
    if has_fuel:
        df['lean']=df.wbo2-df.FFB
        df['acutelean']=df.lean.rolling(W15,min_periods=1).max()>3
    else:
        df['acutelean']=False
    df['loadchg']=(df.load-df.load.shift(W1)).abs()
    df['steady']=(~df.stab)&(~df.acutelean)&(df.loadchg<0.15)
    cz=df[(df.RPM.between(1600,3000))&(df.load.between(1.00,1.25))]
    if len(cz)==0: return dict(res=0,fires=0)
    out=dict(
        res=len(cz)*DT/60,
        fires=int(cz.fire.sum()),
        fires_tr=int(cz[cz.stab].fire.sum()),
        fires_st=int(cz[cz.steady].fire.sum()),
        res_tr=len(cz[cz.stab])*DT/60,
        res_st=len(cz[cz.steady])*DT/60,
        mindepth=cz.FBKC.min(),
        fbkcneg_min=(cz.FBKC<0).sum()*DT/60,   # FBKC<0 samples per min residency
        res_min=len(cz)*DT/60,
    )
    # acute lean + DFCO on in-zone stab onsets
    if has_fuel and 'IPW' in df.columns:
        ons=df.index[(df.accr>40)&(df.accr.shift(1)<=40)]
        leans=[]; dfco=0; nons=0
        for i in ons:
            win=df.loc[i:i+15]
            if not ((win.RPM.between(1600,3000))&(win.load.between(1.0,1.25))).any(): continue
            nons+=1
            leans.append((win.wbo2-win.FFB).max())
            if df.loc[max(0,i-25):i,'IPW'].min()==0: dfco+=1
        out['stab_lean']=np.median(leans) if leans else np.nan
        out['nstabs']=nons
        out['dfco_frac']=dfco/nons if nons else np.nan
    return out

rows=[]
for rev,logs in REV_LOGS.items():
    agg=dict(res=0,fires=0,fires_tr=0,fires_st=0,res_tr=0,res_st=0,fbkcneg=0,mind=0.0,
             leans=[],nstabs=0,dfco=0,nfuel=0)
    md=0.0
    for p in logs:
        r=proc(p)
        if not r: continue
        agg['res']+=r.get('res',0); agg['fires']+=r.get('fires',0)
        agg['fires_tr']+=r.get('fires_tr',0); agg['fires_st']+=r.get('fires_st',0)
        agg['res_tr']+=r.get('res_tr',0); agg['res_st']+=r.get('res_st',0)
        agg['fbkcneg']+=r.get('fbkcneg_min',0)*r.get('res_min',0)
        md=min(md,r.get('mindepth',0) or 0)
        if not np.isnan(r.get('stab_lean',np.nan)):
            agg['leans'].append(r['stab_lean']); agg['nstabs']+=r.get('nstabs',0)
            agg['dfco']+=r.get('dfco_frac',0)*r.get('nstabs',0); agg['nfuel']+=1
    if agg['res']==0: continue
    rows.append(dict(rev=rev, res_min=agg['res'], fires=agg['fires'],
        fire_rate=agg['fires']/agg['res'],
        tr_rate=agg['fires_tr']/agg['res_tr'] if agg['res_tr'] else 0,
        st_rate=agg['fires_st']/agg['res_st'] if agg['res_st'] else 0,
        st_resmin=agg['res_st'],
        mindepth=md,
        fbkcneg_permin=agg['fbkcneg']/agg['res'] if agg['res'] else 0,
        stab_lean=np.median(agg['leans']) if agg['leans'] else np.nan,
        dfco_frac=agg['dfco']/agg['nstabs'] if agg['nstabs'] else np.nan,
        nstabs=agg['nstabs']))

t=pd.DataFrame(rows)
pd.set_option('display.width',200)
print("=== CUSP 1600-3000 x load 1.00-1.25 — longitudinal by rev ===\n")
print(t.to_string(index=False,float_format=lambda x:f'{x:.2f}'))
print("\nLegend: fire_rate=knock-fires/min residency; tr_rate/st_rate=transient vs STEADY knock rate;")
print("st_resmin=steady residency minutes (test power); fbkcneg_permin=FBKC<0 samples/min;")
print("stab_lean=median peak (wbo2-FFB) on in-zone stabs; dfco_frac=in-zone stabs out of fuel-cut.")
