"""
5-28 20.15 full-log knock survey: are FBKC and FLKC two different knock paths,
and is the high-load FLKC 'escalating'?

  - FBKC: fast feedback channel
  - FLKC: slow accumulator channel
Map each to RPM/load and boost-vs-target, and break FLKC into episodes over time.
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df['be'] = df.Trgt_Boost - df.mrp          # +ve = boost UNDER target (spool)

def episodes(mask, gap=25):                 # group consecutive-ish flagged samples
    idx = df.index[mask].tolist();
    if not idx: return []
    eps=[[idx[0]]]
    for i in idx[1:]:
        if i-eps[-1][-1] <= gap: eps[-1].append(i)
        else: eps.append([i])
    return eps

print("=== FBKC<0 (fast path) — where does it fire? ===")
fb=df[df.FBKC<0]
print(f"  n={len(fb)}  min={fb.FBKC.min():.2f}")
print(f"  RPM {fb.RPM.quantile(.1):.0f}-{fb.RPM.quantile(.9):.0f} (med {fb.RPM.median():.0f})")
print(f"  load {fb.load.quantile(.1):.2f}-{fb.load.quantile(.9):.2f} (med {fb.load.median():.2f})")
print(f"  boost-error Trgt-mrp: median {fb.be.median():+.2f} psi  "
      f"(>0 = sub-target/spool)   frac sub-target: {(fb.be>0).mean()*100:.0f}%")
print(f"  frac OVER target (be<0): {(fb.be<0).mean()*100:.0f}%")

print("\n=== FLKC<0 (slow path) — where does it fire? ===")
fl=df[df.FLKC<0]
print(f"  n={len(fl)}  min={fl.FLKC.min():.2f}")
print(f"  RPM {fl.RPM.quantile(.1):.0f}-{fl.RPM.quantile(.9):.0f} (med {fl.RPM.median():.0f})")
print(f"  load {fl.load.quantile(.1):.2f}-{fl.load.quantile(.9):.2f} (med {fl.load.median():.2f})")
print(f"  boost-error: median {fl.be.median():+.2f} psi   frac OVER target (be<0): {(fl.be<0).mean()*100:.0f}%")

print("\n=== FLKC episodes over the drive (escalation check) ===")
for ep in episodes(df.FLKC<0):
    s=df.loc[ep]
    print(f"  t {s.time.min():7.1f}-{s.time.max():7.1f} ({s.time.max()-s.time.min():4.1f}s)  "
          f"min FLKC {s.FLKC.min():5.2f}  RPM {s.RPM.min():.0f}-{s.RPM.max():.0f}  "
          f"peak mrp {s.mrp.max():.1f}  FBKC<0 in ep: {(s.FBKC<0).sum()}")

print("\n=== FBKC episodes (first 8) ===")
for ep in episodes(df.FBKC<0)[:8]:
    s=df.loc[ep]
    print(f"  t {s.time.min():7.1f}-{s.time.max():7.1f}  min FBKC {s.FBKC.min():5.2f}  "
          f"RPM {s.RPM.min():.0f}-{s.RPM.max():.0f}  load {s.load.min():.2f}-{s.load.max():.2f}  "
          f"be med {s.be.median():+.1f}")
