"""
For every knock event in the 5-28 log, characterize the AFR error and whether
a throttle move (tip-in) precedes it.

Questions:
  - Is there an AFR lean event at the knock?  (wbo2 vs FFB = commanded)
  - Tip-in (transient on throttle move) vs open-loop-table (steady lean)?
  - Is throttle moving at the FBKC (spool) events?  -> justifies tip-in work

FFB = Final Fueling Base (commanded AFR). lean_err = wbo2 - FFB  (+ = lean).
wideband lag ~5 samples; compare combustion-time wbo2 to command.
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]
LAG=5
df['lean_err']   = df.wbo2 - df.FFB                  # +ve leaner than commanded
df['lean_lagadj']= df.wbo2.shift(-LAG) - df.FFB      # combustion-time mixture vs cmd
df['thr_rate']   = (df.Throttle.diff()/df.time.diff()).abs()
df['acc_rate']   = (df.Accelerator.diff()/df.time.diff()).abs()

def episodes(mask, gap=25):
    idx=df.index[mask].tolist()
    if not idx: return []
    eps=[[idx[0]]]
    for i in idx[1:]:
        (eps[-1].append(i) if i-eps[-1][-1]<=gap else eps.append([i]))
    return eps

def describe(name, mask):
    print(f"\n===== {name} episodes =====")
    print(f"{'t_start':>8} {'dur':>4} {'RPM':>9} {'loadpk':>6} {'CL/OL':>5} "
          f"{'lean@evt':>8} {'leanPRE':>7} {'thr_rate_pre':>12} {'tip-in?':>7}")
    for ep in episodes(mask):
        s=df.loc[ep]
        i0=ep[0]
        pre=df.loc[max(0,i0-12):i0]                  # ~0.5s before onset
        lean_evt=s.lean_lagadj.max()                 # worst lean during event
        lean_pre=pre.lean_lagadj.max()
        thr_pre =pre.thr_rate.max()
        clol = '/'.join(str(int(x)) for x in s['CL/OL'].unique())
        tip = 'YES' if thr_pre>60 else 'no'
        print(f"{s.time.min():8.1f} {s.time.max()-s.time.min():4.1f} "
              f"{s.RPM.min():4.0f}-{s.RPM.max():<4.0f} {s.load.max():6.2f} {clol:>5} "
              f"{lean_evt:+8.2f} {lean_pre:+7.2f} {thr_pre:12.0f} {tip:>7}")

describe("FBKC<0 (feedback / spool)", df.FBKC<0)
describe("FLKC<0 (learning / high-load)", df.FLKC<0)

# overall: at high load (>2.5 g/rev, in boost), is wbo2 leaner than FFB on average?
hl = df[(df.load>2.5)&(df.mrp>10)]
print(f"\n=== steady high-load (load>2.5, mrp>10): n={len(hl)} ===")
print(f"  commanded FFB: median {hl.FFB.median():.2f}  (min {hl.FFB.min():.2f})")
print(f"  measured wbo2: median {hl.wbo2.median():.2f}")
print(f"  lean_err wbo2-FFB: median {hl.lean_err.median():+.2f}  "
      f"p90 {hl.lean_err.quantile(.9):+.2f}  (>0 = leaner than asked)")
print(f"  frac leaner-than-commanded: {(hl.lean_err>0).mean()*100:.0f}%")
