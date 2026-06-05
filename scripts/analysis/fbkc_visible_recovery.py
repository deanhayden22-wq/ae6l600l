"""
Test Dean's claim: FBKC recovers in slow, VISIBLE 0.35-deg steps (advance value
0.35, delay 70) - i.e. it is NOT a sub-sample transient, so "FBKC=0 in the FLKC
cells" is REAL, not undersampling.

(1) print a clean FBKC event with its full per-sample recovery trace + step sizes
(2) re-confirm the 8249 FLKC retard had genuinely no FBKC (FBKC visible => real)
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]

# (1) find an FBKC event that reaches <= -1.0 then recovers, print the trace
def episodes(mask,gap=15):
    idx=df.index[mask].tolist()
    if not idx: return []
    e=[[idx[0]]]
    for i in idx[1:]:
        (e[-1].append(i) if i-e[-1][-1]<=gap else e.append([i]))
    return e
deep=[ep for ep in episodes(df.FBKC<0) if df.loc[ep].FBKC.min()<=-1.0]
ep=deep[3]                                   # pick one
s=df.loc[max(0,ep[0]-1):ep[-1]+4]
print("=== one FBKC event, full per-sample trace ===")
print(f"{'t':>8} {'RPM':>5} {'load':>5} {'FBKC':>6} {'dFBKC':>6}")
prev=None
for _,r in s.iterrows():
    d = (r.FBKC-prev) if prev is not None else np.nan
    print(f"{r.time:8.2f} {r.RPM:5.0f} {r['load']:5.2f} {r.FBKC:6.2f} {('%+.2f'%d) if prev is not None else '  --':>6}")
    prev=r.FBKC
# recovery step stats
rec=s[s.FBKC<0].FBKC.diff().dropna()
ups=rec[rec>0]
print(f"\nrecovery up-steps seen: {sorted(set(round(x,2) for x in ups))}  (advance value cal = 0.35)")
dt=s.time.diff().median()
print(f"each sample = {dt*1000:.0f} ms; recovery spans {len(ups)} steps over "
      f"{(s[s.FBKC<0].time.max()-s[s.FBKC<0].time.min()):.2f}s  -> MULTI-SAMPLE, visible")

# (2) the 8249 FLKC retard window: FBKC trace
print("\n=== 8249 FLKC episode: FBKC trace (is it really 0?) ===")
w=df[(df.time>=8248.0)&(df.time<=8253.0)]
print(f"FBKC over 8248-8253: min={w.FBKC.min()}, max={w.FBKC.max()}, nonzero samples={ (w.FBKC!=0).sum() }")
print(f"FLKC retard at 8249.48 was within one Fine cell (3400x2.00); FBKC there = "
      f"{df[(df.time>=8249.4)&(df.time<=8249.6)].FBKC.tolist()}")
print(f"nearest FBKC<0 to t=8249.5: {abs(df[df.FBKC<0].time-8249.5).min():.0f}s away")
