"""
Tip-in analysis on the 6-3 20.17 log.

For each throttle tip-in: the boost error at onset (BE = Trgt - mrp, which drives
the tip-in BE compensation), the BE-comp % it lands on (rev-20.17 table), and the
peak lean-of-command (wbo2 - FFB, sensor-lag adjusted) right after.

Question: did raising target to ~17 keep BE high enough to avoid the tip-in
BE-comp attenuation (and therefore avoid the lean spikes)?
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/6-3 20.17/log0001.csv'); df.columns=[c.strip() for c in df.columns]
df['be'] = df.Trgt_Boost - df.mrp
LAG=5
df['lean_lag'] = df.wbo2.shift(-LAG) - df.FFB        # +ve = leaner than commanded at combustion time
df['acc_rate'] = df.Accelerator.diff()/df.time.diff()

# rev-20.17 tip-in BE comp table (axis psi -> comp %)
BE_AX=[0,0.93,1.86,2.79,3.71,4.64,5.57,6.50,6.73]
BE_CP=[-90.6,-87.5,-81.2,-73.4,-63.3,-50.0,-32.0,-5.5,0.0]
def be_comp(be):
    if be<=0: return BE_CP[0]
    if be>=BE_AX[-1]: return 0.0
    return float(np.interp(be,BE_AX,BE_CP))

# detect tip-in onsets: pedal rising fast
df['tip']=(df.acc_rate>60)
onsets=[]
prev=False
for i,v in zip(df.index,df.tip):
    if v and not prev: onsets.append(i)
    prev=v
print(f"tip-in onsets detected (acc_rate>60 %/s): {len(onsets)}")
rows=[]
for i in onsets:
    win=df.loc[i:i+15]                               # ~0.6s after onset
    r=df.loc[i]
    rows.append(dict(t=r.time,RPM=r.RPM,load=r['load'],
                     acc_from=df.loc[max(0,i-1),'Accelerator'],acc_to=win.Accelerator.max(),
                     BE=r.be, comp=be_comp(r.be), peak_lean=win.lean_lag.max()))
t=pd.DataFrame(rows)
print(f"\nBE at tip-in onset: median {t.BE.median():.1f} psi  (>6.73 = comp NEUTRAL = full tip-in)")
print(f"tip-ins in the BE-comp ATTENUATION zone (BE<6.73): {(t.BE<6.73).sum()}/{len(t)}")
print(f"  of those, median BE-comp = {t[t.BE<6.73].comp.median():.0f}% (tip-in cut by that much)")
print(f"peak lean-of-command after tip-in: median {t.peak_lean.median():+.2f}  p90 {t.peak_lean.quantile(.9):+.2f} AFR")
print(f"tip-ins with a real lean spike (>+1.0 AFR): {(t.peak_lean>1.0).sum()}/{len(t)}")
print("\n=== worst 12 tip-in lean events ===")
w=t.nlargest(12,'peak_lean')[['t','RPM','load','acc_from','acc_to','BE','comp','peak_lean']]
print(w.to_string(index=False,float_format=lambda x:f'{x:.2f}'))
