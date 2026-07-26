#!/usr/bin/env python3
"""
load_comp_tool.py -- Engine Load Compensation (MP) data-driven review tool.

Buckets the (clean-PCV) driving corpus by RPM x manifold pressure, measures the fueling
error against the CURRENT table, and reports REQUIRED-TOTAL comp (= current + error) so the
direction to move each cell is explicit. Uses EVERYTHING via a path-based classification.

FUELING-ERROR legs (POSITIVE = ran LEAN = wants MORE fuel = raise comp;
                     NEGATIVE = ran RICH = wants LESS fuel = lower comp):
  Path is classified by whether the O2 loop is ACTUALLY closed, not by the logged CL/OL flag
  (the flag lies: ~57% of CL/OL==8 samples are rich-commanded, loop frozen -> running OL terms):
    real-CL  = (CL/OL==8) AND (cl_ffb <= FFB <= 15.5)      -> corr = AFC + AFL
               (true stoich closed loop; wbo2 is masked by the loop, so the trim reveals the error)
    eff-OL   = (CL/OL==10) OR ((CL/OL==8) AND FFB < cl_ffb) -> corr = (1 - FFB/wbo2_lag3)*100
               (loop open or frozen; wbo2 vs command IS the error)
  NOTE the (1-FFB/wbo2) leg = 1 - estimated_air/actual_air (target AFR cancels): it is the
  airflow(+injector) error the comp lever moves. Both legs also absorb injector/MAF-high-flow
  error (the pre-swap issue) -- that confound hits CL and OL equally; interpret big boost-region
  numbers with the injector swap in mind.

REQUIRED-TOTAL = current_comp(cell) + measured_error(cell). This is what the comp "wants" to be.
  delta = required - current = the measured error = which way (and how far) to move the cell.

Verified constants (2026-07-25): recompute (stored `correction` is inconsistent); wbo2 lag 3
within src segment; MP axis = MAP_abs - 14.696 (=~ mrp - 0.19); table byte-identical 20.18..20.19a,
Cruise==NonCruise; LSB 0.390625%; axes float32 mmHg.

Usage:
  python load_comp_tool.py                 # clean-PCV corpus (6-21+), path-based, both figures
  python load_comp_tool.py --all           # every rev-mapped log (incl PCV-leak era!)
  python load_comp_tool.py --cl-ffb 14.4 --min-n 50 --dtps 2
"""
import argparse, os, sys, struct
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm

HERE=os.path.dirname(os.path.abspath(__file__))
def repo(*p):
    root=os.environ.get("AE_ROOT") or os.path.abspath(os.path.join(HERE,"..",".."))
    return os.path.join(root,*p)

CR_MP,CR_RPM,CR_TBL=0xC3BD8,0xC3C04,0xC3C3C
NMP,NRPM=11,14
MMHG2PSI,SEA,LSB=0.0193368,14.696,0.390625

def read_current_table(binpath):
    rom=open(binpath,"rb").read()
    mp=struct.unpack(">%df"%NMP,rom[CR_MP:CR_MP+4*NMP])
    rpm=struct.unpack(">%df"%NRPM,rom[CR_RPM:CR_RPM+4*NRPM])
    b=rom[CR_TBL:CR_TBL+NMP*NRPM]
    tbl=np.array([[(b[r*NMP+c]-128)*LSB for c in range(NMP)] for r in range(NRPM)])
    return np.array(rpm),np.array([x*MMHG2PSI-SEA for x in mp]),tbl

def bilinear_current(rpm_axis,mp_axis,cur,rpm_pts,mp_pts):
    """interp current table (14x11) onto grid rpm_pts x mp_pts (clamped to edges)."""
    tmp=np.vstack([np.interp(mp_pts,mp_axis,cur[i,:]) for i in range(len(rpm_axis))]) # [14, nmp]
    out=np.vstack([np.interp(rpm_pts,rpm_axis,tmp[:,j]) for j in range(len(mp_pts))]).T # [nrpm,nmp]
    return out

def select_logs(since=None,alllogs=False,explicit=None):
    if explicit: return [(p,"?",None) for p in explicit]
    m=pd.read_csv(repo("logs","rom_rev_map.csv"),dtype=str)
    m["d"]=pd.to_datetime(m["log_date"],errors="coerce")
    if not alllogs: m=m[m["d"]>=pd.to_datetime(since or "2026-06-21")]
    out=[]
    for _,r in m.iterrows():
        p=repo("logs",r["log_path"])
        (out.append((p,r["rom_rev"],r["log_date"])) if os.path.exists(p)
         else print(f"  [skip missing] {r['log_path']}",file=sys.stderr))
    return out

def compute_correction(df,dtps=2.0,app_min=2.0,corr_clip=25.0,ect_min=160.0,wbo2_lag=3,
                       tps_col="Throttle",steady=True,win=25,tps_std=1.0,rpm_std=75.0,
                       mp_std=0.40,cl_ffb=14.4):
    df=df.copy()
    for c in ["wbo2","FFB","AFC","AFL","RPM","MAP","Accelerator",tps_col,"CL/OL","ECT"]:
        if c in df.columns: df[c]=pd.to_numeric(df[c],errors="coerce")
    seg=df["src"].astype(str) if "src" in df.columns else \
        df.get("seam",pd.Series(0,index=df.index)).fillna(0).astype(int).cumsum()
    df["wbo2_lag"]=df.groupby(seg)["wbo2"].shift(-wbo2_lag)
    dtps_series=df.groupby(seg)[tps_col].diff().abs()
    clol=df["CL/OL"]; ffb=df["FFB"]
    real_cl=(clol==8)&(ffb>=cl_ffb)&(ffb<=15.5)
    eff_ol =(clol==10)|((clol==8)&(ffb<cl_ffb))
    corr=pd.Series(np.nan,index=df.index)
    corr[real_cl]=df.loc[real_cl,"AFC"]+df.loc[real_cl,"AFL"]
    corr[eff_ol] =(1.0-df.loc[eff_ol,"FFB"]/df.loc[eff_ol,"wbo2_lag"])*100.0
    df["corr"]=corr
    df["mode"]=np.where(real_cl,"CL",np.where(eff_ol,"OL","other"))
    df["mp_rel"]=df["MAP"]-SEA
    keep=(df["corr"].notna()&(df["corr"].abs()<corr_clip)&
          (ffb>=8)&(ffb<=16)&(df["wbo2"]>8)&(df["wbo2"]<19)&
          (df["Accelerator"]>app_min)&(dtps_series<=dtps)&(df["mode"]!="other"))
    if "ECT" in df.columns: keep&=((df["ECT"]>=ect_min)|df["ECT"].isna())
    if steady:
        g=df.groupby(seg)
        keep&=(g[tps_col].transform(lambda s:s.rolling(win,center=True,min_periods=win).std())<tps_std)
        keep&=(g["RPM"].transform(lambda s:s.rolling(win,center=True,min_periods=win).std())<rpm_std)
        keep&=(g["mp_rel"].transform(lambda s:s.rolling(win,center=True,min_periods=win).std())<mp_std)
    df["keep"]=keep.fillna(False)
    return df[["RPM","mp_rel","corr","mode","keep"]]

def grid_modes(d,rpm_edges,mp_edges):
    d=d[(d["RPM"]>=rpm_edges[0])&(d["RPM"]<rpm_edges[-1])&
        (d["mp_rel"]>=mp_edges[0])&(d["mp_rel"]<mp_edges[-1])].copy()
    d["ri"]=np.digitize(d["RPM"],rpm_edges)-1; d["mi"]=np.digitize(d["mp_rel"],mp_edges)-1
    nR,nM=len(rpm_edges)-1,len(mp_edges)-1; res={}
    for mode in ["OL","CL","all"]:
        sub=d if mode=="all" else d[d["mode"]==mode]
        med=np.full((nR,nM),np.nan); cnt=np.zeros((nR,nM))
        if len(sub):
            g=sub.groupby(["ri","mi"])["corr"]
            for (a,b),v in g.median().items():
                if 0<=a<nR and 0<=b<nM: med[a,b]=v
            for (a,b),v in g.size().items():
                if 0<=a<nR and 0<=b<nM: cnt[a,b]=v
        res[mode]=(med,cnt)
    return res

def cells_modes(d,rpm_axis,mp_axis):
    d=d.copy()
    d["ri"]=[int(np.argmin(np.abs(rpm_axis-v))) for v in d["RPM"].values]
    d["mi"]=[int(np.argmin(np.abs(mp_axis-v))) for v in d["mp_rel"].values]
    nR,nM=len(rpm_axis),len(mp_axis); res={}
    for mode in ["OL","CL","all"]:
        sub=d if mode=="all" else d[d["mode"]==mode]
        med=np.full((nR,nM),np.nan); cnt=np.zeros((nR,nM))
        if len(sub):
            g=sub.groupby(["ri","mi"])["corr"]
            for (a,b),v in g.median().items(): med[a,b]=v
            for (a,b),v in g.size().items(): cnt[a,b]=v
        res[mode]=(med,cnt)
    return res

def heat(ax,rpm_edges,mp_edges,med,cnt,rpm_axis,mp_axis,cur,title,min_n,vmax=None,marks=True):
    m=np.ma.masked_invalid(np.where(cnt>=min_n,med,np.nan))
    if vmax is None:
        vmax=max(2.0,np.nanpercentile(np.abs(m.filled(np.nan)),98)) if np.isfinite(m).any() else 8
    X,Y=np.meshgrid(rpm_edges,mp_edges)
    pc=ax.pcolormesh(X,Y,m.T,cmap="RdBu_r",norm=TwoSlopeNorm(vmin=-vmax,vcenter=0,vmax=vmax),shading="flat")
    for r in rpm_axis: ax.axvline(r,color="k",lw=0.3,alpha=0.22)
    for mp in mp_axis: ax.axhline(mp,color="k",lw=0.3,alpha=0.22)
    if marks:
        for i,r in enumerate(rpm_axis):
            for j,mp in enumerate(mp_axis):
                if cur[i,j]>0.2: ax.plot(r,mp,marker="s",ms=2.0,mec="k",mfc="none",mew=0.5,alpha=0.55)
    ax.set_title(title,fontsize=10); ax.set_xlabel("RPM"); ax.set_ylabel("MP (psi rel sea level)")
    ax.set_xlim(rpm_edges[0],rpm_edges[-1]); ax.set_ylim(mp_edges[0],mp_edges[-1])
    plt.colorbar(pc,ax=ax,label="% (+lean/-rich)")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--since",default="2026-06-21"); ap.add_argument("--all",action="store_true")
    ap.add_argument("--logs",nargs="*"); ap.add_argument("--bin",default=None)
    ap.add_argument("--dtps",type=float,default=2.0); ap.add_argument("--app-min",type=float,default=2.0)
    ap.add_argument("--min-n",type=int,default=50); ap.add_argument("--cl-ffb",type=float,default=14.4)
    ap.add_argument("--tag",default="cleanpcv"); ap.add_argument("--out",default=None)
    ap.add_argument("--staged-root",default=None); ap.add_argument("--no-steady",action="store_true")
    a=ap.parse_args()
    if a.staged_root: os.environ["AE_ROOT"]=a.staged_root
    binp=a.bin or repo("rom","AE5L600L 20g rev 20.19.bin")
    outdir=a.out or repo("scripts","analysis","trends"); os.makedirs(outdir,exist_ok=True)

    rpm_axis,mp_axis,cur=read_current_table(binp)
    logs=select_logs(a.since,a.all,a.logs)
    print(f"Loading {len(logs)} logs; cl_ffb={a.cl_ffb}:")
    frames=[]
    for p,rev,dt in logs:
        d=compute_correction(pd.read_csv(p,low_memory=False),dtps=a.dtps,app_min=a.app_min,
                             steady=not a.no_steady,cl_ffb=a.cl_ffb)
        k=d[d["keep"]]
        print(f"  {os.path.basename(p):34s} {str(rev):7s} kept {len(k):>6d}  (CL {int((k['mode']=='CL').sum()):>6d} / OL {int((k['mode']=='OL').sum()):>6d})")
        frames.append(k)
    d=pd.concat(frames,ignore_index=True)
    print(f"TOTAL kept: {len(d):,}  (CL {int((d['mode']=='CL').sum()):,} / OL {int((d['mode']=='OL').sum()):,})")

    rpm_edges=np.arange(1000,5001,100); mp_edges=np.round(np.arange(-11,6.01,0.25),2)
    rc=(rpm_edges[:-1]+rpm_edges[1:])/2; mc=(mp_edges[:-1]+mp_edges[1:])/2
    fg=grid_modes(d,rpm_edges,mp_edges); cg=cells_modes(d,rpm_axis,mp_axis)
    cur_fine=bilinear_current(rpm_axis,mp_axis,cur,rc,mc)

    # required-total fine grid = current(interp) + unified error
    allmed,allcnt=fg["all"]
    req_fine=np.where(allcnt>=a.min_n, cur_fine+allmed, np.nan)

    # per-cell CSV
    rows=[]
    for i,r in enumerate(rpm_axis):
        for j,mp in enumerate(mp_axis):
            olm,oln=cg["OL"][0][i,j],cg["OL"][1][i,j]; clm,cln=cg["CL"][0][i,j],cg["CL"][1][i,j]
            am,an=cg["all"][0][i,j],cg["all"][1][i,j]
            edge=(i in (0,NRPM-1)) or (j in (0,NMP-1))
            req=cur[i,j]+am if (an>=a.min_n and np.isfinite(am)) else np.nan
            prop=cur[i,j]
            if (not edge) and an>=a.min_n and np.isfinite(am):
                prop=round((cur[i,j]+am)/LSB)*LSB
            rows.append(dict(rpm=int(r),mp=round(float(mp),2),current=round(float(cur[i,j]),2),
                cl_err=None if not np.isfinite(clm) else round(float(clm),2),cl_n=int(cln),
                ol_err=None if not np.isfinite(olm) else round(float(olm),2),ol_n=int(oln),
                unified_err=None if not np.isfinite(am) else round(float(am),2),n=int(an),
                required_total=None if not np.isfinite(req) else round(float(req),2),
                proposed=round(float(prop),2),delta=round(float(prop-cur[i,j]),2)))
    pd.DataFrame(rows).to_csv(os.path.join(outdir,f"load_comp_cells_{a.tag}.csv"),index=False)

    # fine hotspots CSV (per mode)
    fr=[]
    for i in range(len(rc)):
        for j in range(len(mc)):
            for mode in ["OL","CL","all"]:
                med,cnt=fg[mode]
                if cnt[i,j]>0:
                    fr.append(dict(rpm=int(rc[i]),mp=round(float(mc[j]),2),mode=mode,
                                   err=round(float(med[i,j]),2),n=int(cnt[i,j])))
    pd.DataFrame(fr).to_csv(os.path.join(outdir,f"load_comp_hotspots_{a.tag}.csv"),index=False)

    # FIGURE 1: unified error + required-total
    fig,ax=plt.subplots(1,2,figsize=(17,6.5))
    heat(ax[0],rpm_edges,mp_edges,*fg["all"],rpm_axis,mp_axis,cur,
         f"Unified fueling error (path-based)  □=current comp>0",a.min_n)
    m=np.ma.masked_invalid(req_fine); vmax=max(3,np.nanpercentile(np.abs(m.filled(np.nan)),98)) if np.isfinite(m).any() else 8
    X,Y=np.meshgrid(rpm_edges,mp_edges)
    pc=ax[1].pcolormesh(X,Y,m.T,cmap="RdBu_r",norm=TwoSlopeNorm(vmin=-vmax,vcenter=0,vmax=vmax),shading="flat")
    for r in rpm_axis: ax[1].axvline(r,color="k",lw=0.3,alpha=0.22)
    for mp in mp_axis: ax[1].axhline(mp,color="k",lw=0.3,alpha=0.22)
    ax[1].set_title("REQUIRED-TOTAL comp = current + error  (what the comp wants to be)",fontsize=10)
    ax[1].set_xlabel("RPM"); ax[1].set_ylabel("MP (psi rel sea level)")
    ax[1].set_xlim(1000,5000); ax[1].set_ylim(-11,6); plt.colorbar(pc,ax=ax[1],label="% comp")
    fig.suptitle(f"Engine Load Comp — {a.tag} — path-based (rich CL8->OL math), dTPS≤2+steady, "
                 f"min_n={a.min_n} | kept {len(d):,}",fontsize=11)
    fig.tight_layout(); fig.savefig(os.path.join(outdir,f"load_comp_required_{a.tag}.png"),dpi=115); plt.close(fig)

    # FIGURE 2: CL vs OL split (transparency on airflow-dependence)
    fig,ax=plt.subplots(1,2,figsize=(17,6.5))
    heat(ax[0],rpm_edges,mp_edges,*fg["CL"],rpm_axis,mp_axis,cur,"real-CL trim (AFC+AFL)",a.min_n,vmax=8)
    heat(ax[1],rpm_edges,mp_edges,*fg["OL"],rpm_axis,mp_axis,cur,"eff-OL (1-FFB/wbo2)",a.min_n,vmax=8)
    fig.suptitle(f"CL vs OL split — {a.tag} — where they disagree = airflow-dependence within a cell",fontsize=11)
    fig.tight_layout(); fig.savefig(os.path.join(outdir,f"load_comp_clol_split_{a.tag}.png"),dpi=115); plt.close(fig)

    print("\nWROTE (out dir):",outdir)
    # console: biggest required-total moves inside coverage
    cells=[r for r in rows if r["n"]>=a.min_n and r["delta"] is not None and abs(r["delta"])>=1]
    cells.sort(key=lambda x:-abs(x["delta"]))
    print(f"\nBiggest proposed moves (|delta|>=1%, n>=min_n): {len(cells)} cells")
    print("  rpm    mp  current  unified_err  required  proposed  delta   n   (cl_n/ol_n)")
    for r in cells[:16]:
        print(f"  {r['rpm']:5d} {r['mp']:5.2f} {r['current']:7.2f} {str(r['unified_err']):>10s}  {str(r['required_total']):>8s} {r['proposed']:8.2f} {r['delta']:+6.2f} {r['n']:6d}  ({r['cl_n']}/{r['ol_n']})")

if __name__=="__main__": main()
