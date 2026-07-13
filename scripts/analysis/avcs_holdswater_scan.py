#!/usr/bin/env python3
"""
Does the AVCS-plateau knock story hold across the corpus, or was it conditions?
Per log: median ACTUAL cam at the knock box (steady samples -> reveals the
table each log actually ran, incl. binless 20.7), cusp deep-event rate, IAT.
Resumable -> trends/avcs_holdswater.csv
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parent))
from log_review_ingest import load_log, detect_sample_rate
REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "trends" / "avcs_holdswater.csv"

def one(path, rev, date):
    df = load_log(path)
    if not {'RPM','load','FBKC','avcs'}.issubset(df.columns): return None
    sps = detect_sample_rate(df['time'].to_numpy())
    warm = df['ECT']>170 if 'ECT' in df.columns else pd.Series(True,index=df.index)
    box = warm & df['RPM'].between(2000,3200) & df['load'].between(1.0,1.35)
    rstd = df['RPM'].rolling(int(sps)).std()
    steady_box = box & (rstd<60) & (df['avcs']>0)
    cam_med = float(df.loc[steady_box,'avcs'].median()) if steady_box.sum()>=50 else np.nan
    cam_n = int(steady_box.sum())
    # cusp zone deep events (first-instance onset, depth<=-3)
    fb = df['FBKC'].to_numpy(); n=len(fb)
    onset = (fb<0)&(np.roll(fb,1)==0); onset[0]=False
    cusp = (df['RPM'].between(1600,3000)&df['load'].between(1.0,1.25)).to_numpy()
    res_min = cusp.sum()/sps/60
    fires=deep=0
    for i in np.where(onset&cusp)[0]:
        j=i
        while j<n-1 and fb[j]<0: j+=1
        fires+=1
        if fb[i:j].min()<=-3 if j>i else fb[i]<=-3: deep+=1
    iat = float(df['IAT'].median()) if 'IAT' in df.columns else np.nan
    return dict(log_date=date, rom_rev=rev,
        log_path=str(path.relative_to(REPO)).replace("\\","/"),
        cam_at_box_med=round(cam_med,1) if cam_med==cam_med else np.nan, cam_n=cam_n,
        cusp_res_min=round(res_min,2), cusp_fires=fires, cusp_deep=deep,
        deep_per_min=round(deep/res_min,3) if res_min>=1 else np.nan,
        iat_med=iat)

def main():
    m = pd.read_csv(REPO/"logs/rom_rev_map.csv")
    rows=[]; done=set()
    if OUT.exists():
        prev=pd.read_csv(OUT); rows=prev.to_dict("records"); done=set(prev['log_path'])
    budget=7
    for _,r in m.iterrows():
        if budget==0: break
        p = REPO/"logs"/r['log_path']; rel=f"logs/{r['log_path']}"
        if rel in done or not p.exists(): continue
        try: row=one(p,str(r['rom_rev']),str(r['log_date']))
        except Exception as e: print("ERR",rel,e); done.add(rel); continue
        if row:
            rows.append(row)
            print(f"{row['log_date']} {row['rom_rev']:>7s} cam@box {row['cam_at_box_med']} (n={row['cam_n']:5d})  cusp {row['cusp_fires']:3d}f/{row['cusp_deep']}d in {row['cusp_res_min']:5.1f}min  IAT {row['iat_med']}")
        done.add(rel); budget-=1
    pd.DataFrame(rows).to_csv(OUT,index=False)
    rem=sum(1 for _,r in m.iterrows() if f"logs/{r['log_path']}" not in done and (REPO/"logs"/r['log_path']).exists())
    print(f"remaining {rem}")

if __name__=="__main__": main()
