"""
All FLKC events in the 5-28 log, on the *correct* Fine Correction grid:
  rows (RPM)  = 1600 2200 2800 3400 4000 4600
  cols (load) = 0.75 1.10 1.50 2.00   (top col catches load up to range edge 3.45)

Per episode: cells touched, peak retard, count of real knock retard events
(down-steps; with Retard Value 1.01 each ~1.0deg drop = 1 knock), KNOCK_FLAG
events, and whether FBKC fired. Plus a spatial map: do FLKC<0, FBKC<0 and
KNOCK_FLAG occupy the same RPM/load cells?
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]
ROWS=[1600,2200,2800,3400,4000,4600]; COLS=[0.75,1.10,1.50,2.00]
def binr(v,ax):
    i=np.searchsorted(ax,v,side='right')-1
    return ax[i] if i>=0 else None
df['frow']=df.RPM.apply(lambda v:binr(v,ROWS))
df['fcol']=df.load.apply(lambda v:binr(v,COLS))
df['kflag']=(df.KNOCK_FLAG!=0)
print('KNOCK_FLAG distinct values:', sorted(df.KNOCK_FLAG.unique())[:8], ' total nz:', df.kflag.sum())

def eps(mask,gap=25):
    idx=df.index[mask].tolist()
    if not idx: return []
    e=[[idx[0]]]
    for i in idx[1:]:
        (e[-1].append(i) if i-e[-1][-1]<=gap else e.append([i]))
    return e

print("\n===== ALL FLKC<0 EPISODES =====")
print(f"{'t_start':>8} {'dur':>4} {'cells (RPMrow x loadcol)':<34} {'pkFLKC':>6} "
      f"{'retardEvts':>10} {'KFLAG':>5} {'FBKC<0':>6}")
tot_evt=0
for ep in eps(df.FLKC<0):
    s=df.loc[ep]
    # extend a few samples before to catch the onset cell
    s2=df.loc[max(0,ep[0]-3):ep[-1]+3]
    drops=(s.FLKC.diff()<0)                      # downward steps within episode
    big_drops=(s.FLKC.diff()<=-0.75)             # ~ one 1.01 retard
    cells=sorted(set((int(r),c) for r,c in zip(s.frow.fillna(0),s.fcol.fillna(0)) if r))
    cstr=' '.join(f'{r}x{c:.2f}' for r,c in cells)
    tot_evt+=int(big_drops.sum())
    print(f"{s.time.min():8.1f} {s.time.max()-s.time.min():4.1f} {cstr:<34} "
          f"{s.FLKC.min():6.2f} {int(big_drops.sum()):10d} {int(s2.kflag.sum()):5d} {int((s.FBKC<0).sum()):6d}")
print(f"\nTotal ~1.0deg retard events across all FLKC episodes: {tot_evt}")

# ---- spatial maps -------------------------------------------------------
def grid(mask,label):
    sub=df[mask]
    print(f"\n--- {label}: samples per Fine cell (RPMrow down, loadcol across) ---")
    hdr='RPM\\load '+''.join(f'{c:>7.2f}' for c in COLS)
    print(hdr)
    for r in ROWS:
        row=sub[sub.frow==r]
        cnts=[ (row.fcol==c).sum() for c in COLS ]
        print(f'{r:>8} '+''.join(f'{n:>7d}' for n in cnts))
grid(df.FLKC<0, 'FLKC<0 (fine, high-load)')
grid(df.FBKC<0, 'FBKC<0 (feedback)')
grid(df.kflag,  'KNOCK_FLAG')

# overlap test
fl=set(zip(df[df.FLKC<0].frow,df[df.FLKC<0].fcol))
fb=set(zip(df[df.FBKC<0].frow,df[df.FBKC<0].fcol))
print('\nFine cells with FLKC<0:', sorted((int(r),c) for r,c in fl if r==r and r))
print('Fine cells with FBKC<0:', sorted((int(r),c) for r,c in fb if r==r and r))
print('OVERLAP (both):', sorted((int(r),c) for r,c in (fl&fb) if r==r and r))
