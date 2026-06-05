"""
Fresh-flash test: FLKC starts at 0, so ALL fine correction in this log was
built THIS session, which (per the FBKC->FLKC mechanism) requires FBKC to have
fired first in those cells.

Test: (1) confirm FLKC=0 at start and the onset time.
      (2) for every cell that EVER shows FLKC<0, did that cell ALSO show FBKC<0,
          and did the FBKC come first in time?
      (3) any FLKC<0 cell with NO FBKC<0 (would break the rule)?
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]
ROWS=[1600,2200,2800,3400,4000,4600]; COLS=[0.75,1.10,1.50,2.00]
b=lambda v,ax:(ax[np.searchsorted(ax,v,side='right')-1] if np.searchsorted(ax,v,side='right')-1>=0 else None)
df['frow']=df.RPM.apply(lambda v:b(v,ROWS)); df['fcol']=df.load.apply(lambda v:b(v,COLS))

print("(1) FRESH-FLASH BASELINE")
print(f"    FLKC at first sample (t={df.time.iloc[0]:.0f}): {df.FLKC.iloc[0]}")
print(f"    FLKC stays 0 until t={df[df.FLKC<0].time.min():.0f}")
print(f"    FBKC first <0 at t={df[df.FBKC<0].time.min():.0f}  (well before FLKC)")
# high-load operation BEFORE first FLKC<0 ?
t_flkc=df[df.FLKC<0].time.min()
pre=df[(df.time<t_flkc)]
preHL=pre[(pre.load>=2.0)&(pre.RPM.between(3000,3800))]
print(f"    high-load (load>=2.0, 3000-3800rpm) samples BEFORE first FLKC: {len(preHL)}, "
      f"of which FBKC<0: {(preHL.FBKC<0).sum()}  (knock building fine corr)")

print("\n(2)/(3) PER FLKC<0 CELL: did FBKC fire there, and first?")
print(f"{'cell':<16}{'FLKC<0 n':>9}{'FBKC<0 n':>9}{'1stFBKC t':>10}{'1stFLKC t':>10}{'FBKC first?':>12}")
viol=[]
for r in ROWS:
    for c in COLS:
        cell=df[(df.frow==r)&(df.fcol==c)]
        fl=cell[cell.FLKC<0]; fb=cell[cell.FBKC<0]
        if len(fl)==0: continue
        t_fb = fb.time.min() if len(fb) else np.nan
        t_fl = fl.time.min()
        ok = ('yes' if len(fb) and t_fb<=t_fl else ('SAME-CELL no FBKC' if len(fb)==0 else 'FLKC first?!'))
        if len(fb)==0: viol.append((r,c,len(fl)))
        print(f"{str(r)+'x'+f'{c:.2f}':<16}{len(fl):>9}{len(fb):>9}"
              f"{(f'{t_fb:.0f}' if len(fb) else '--'):>10}{t_fl:>10.0f}{ok:>12}")
print("\nFLKC<0 cells with ZERO FBKC<0 ever (rule-breakers):",
      [(r,c,n) for r,c,n in viol] or "NONE")
