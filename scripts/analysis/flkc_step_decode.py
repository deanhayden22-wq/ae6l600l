"""
Decode the exact FLKC trace through the high-load event and test it against the
configured Fine Correction calibration (rev 20.15 == 20.17):
    Retard Value  = 1.01 deg/knock
    Advance Value = 0.25 deg/step
    Advance Delay = 90 counts (pipeline runs once per engine cycle = 2 rev)
    log LSB        = 0.25 deg (P91 byte)

Each FLKC change is reported with dt, the implied engine-cycles elapsed at the
current RPM, and the step in LSBs, so we can see whether down-steps == 1 knock
(1.01 deg ~ 4 LSB) and whether advance timing matches the 90-count delay.
"""
import pandas as pd, numpy as np
df = pd.read_csv('logs/5-28 20.15/log0001.csv'); df.columns=[c.strip() for c in df.columns]
w = df[(df.time>=8248.8)&(df.time<=8253.2)].reset_index(drop=True)

RETARD=1.01; ADVANCE=0.25; DELAY=90; LSB=0.25
prev=None; prev_t=None
print(f"{'t':>8} {'RPM':>5} {'load':>5} {'FLKC':>6} {'dFLKC':>6} {'LSB':>4} "
      f"{'dt_s':>5} {'cyc@rpm':>7}  interpretation")
for _,r in w.iterrows():
    if prev is None or r.FLKC!=prev:
        if prev is not None:
            d=r.FLKC-prev; dt=r.time-prev_t
            cyc=dt/( (2*60)/r.RPM )          # engine cycles in dt (cycle=2 rev)
            lsb=d/LSB
            if d<0:
                knocks=abs(d)/RETARD
                interp=f"RETARD x{knocks:.1f} knock event(s) @1.01"
            else:
                steps=d/ADVANCE
                interp=f"ADVANCE {steps:.0f}x0.25 over {cyc:.0f} cyc (delay={DELAY})"
            print(f"{r.time:8.2f} {r.RPM:5.0f} {r['load']:5.2f} {r.FLKC:6.2f} "
                  f"{d:+6.2f} {lsb:+4.0f} {dt:5.2f} {cyc:7.1f}  {interp}")
        else:
            print(f"{r.time:8.2f} {r.RPM:5.0f} {r['load']:5.2f} {r.FLKC:6.2f} "
                  f"{'--':>6} {'--':>4} {'--':>5} {'--':>7}  (first sample)")
        prev=r.FLKC; prev_t=r.time

# resolution check
for rpm in [3500]:
    cyc_s = (2*60)/rpm
    print(f"\n@ {rpm} rpm: 1 engine cycle = {cyc_s*1000:.1f} ms; "
          f"90-count delay = {90*cyc_s:.2f} s; log sample = 40 ms")
    print(f"  -> 90-count INITIAL delay ({90*cyc_s:.1f}s) is easily resolved at 25 Hz")
    print(f"  -> but per-cycle advance after the delay ({cyc_s*1000:.0f} ms) is BELOW the 40 ms log -> aliases into a fast ramp")
